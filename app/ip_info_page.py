"""Open the maintained echoip service in the browser's own network context.

This uses mpolden/echoip's public deployment rather than adding a local web
server, scripts, extensions or a second browser networking stack.
"""
import math
import time

from local_state import LocalBrowserError

IP_INFO_URL='https://ifconfig.co/'
_INFO_URLS=frozenset((IP_INFO_URL,IP_INFO_URL.rstrip('/')))
IP_INFO_OPERATIONS=frozenset(('Target.getTargets','Target.attachToTarget','Page.reload',
    'Target.detachFromTarget','Target.createTarget','Target.closeTarget','Target.activateTarget'))
IP_INFO_CAUSE_TYPES=frozenset(('LocalBrowserError','OSError','TimeoutError','ConnectionError',
    'ConnectionResetError','ConnectionAbortedError','ConnectionRefusedError','BrokenPipeError',
    'WebSocketException','WebSocketTimeoutException','WebSocketConnectionClosedException',
    'WebSocketBadStatusException','JSONDecodeError','ValueError','TypeError','KeyError','RuntimeError'))


def _failure(error,operation):
    failure=LocalBrowserError('IP信息页操作未完成。')
    failure.code='ip_info_failed'
    failure.operation=operation if operation in IP_INFO_OPERATIONS else 'unknown'
    name=type(error).__name__
    failure.cause_type=name if name in IP_INFO_CAUSE_TYPES else 'Exception'
    return failure


def _call(connection,operation,params=None,*,session=None,receipt=None):
    try:
        options={'session':session} if session is not None else {}
        result=connection.call(operation,params,**options) if params is not None else connection.call(operation,**options)
        if not isinstance(result,dict):raise ValueError()
        if receipt:
            value=result.get(receipt)
            if not isinstance(value,str) or not value:raise ValueError()
            return value
        return result
    except Exception as error:
        raise _failure(error,operation) from None


def _targets(connection):
    result=_call(connection,'Target.getTargets')
    try:
        pages=result['targetInfos']
        if not isinstance(pages,list):raise ValueError()
        targets={page['targetId']:page for page in pages}
        if len(targets)!=len(pages) or any(not isinstance(identity,str) or not identity for identity in targets):raise ValueError()
        return targets
    except Exception as error:raise _failure(error,'Target.getTargets') from None


def _info(page):
    return page is not None and page.get('type')=='page' and page.get('url') in _INFO_URLS


def _confirmation_budget(connection):
    timeout=getattr(connection,'timeout',5)
    return min(5,timeout) if type(timeout) in (int,float) and math.isfinite(timeout) and timeout>0 else 5


def _within_confirmation(connection,deadline,action):
    remaining=deadline-time.monotonic()
    if remaining<=0:raise _failure(TimeoutError(),'Target.getTargets')
    missing=object();previous=getattr(connection,'timeout',missing)
    try:
        connection.timeout=remaining
        return action()
    finally:
        if previous is missing:del connection.timeout
        else:connection.timeout=previous


def _confirmation_targets(connection,deadline):
    return _within_confirmation(connection,deadline,lambda:_targets(connection))


def _confirmed(connection,target,deadline,*,creating=False,closed=(),previous=()):
    while True:
        current=_confirmation_targets(connection,deadline)
        page=current.get(target)
        if not _info(page):
            if not creating or (page is not None and (page.get('type')!='page' or page.get('url') not in ('','about:blank'))):
                raise _failure(ValueError(),'Target.getTargets')
        elif not any(identity in current for identity in closed):
            if any(_info(current.get(identity)) for identity in previous):
                raise _failure(ValueError(),'Target.getTargets')
            return current
        remaining=deadline-time.monotonic()
        if remaining<=0:raise _failure(TimeoutError(),'Target.getTargets')
        time.sleep(min(.05,remaining))


def show_ip_info(connection):
    """Confirm a fresh info page before retiring the first old exact info page."""
    before=_targets(connection)
    previous=[identity for identity,page in before.items() if _info(page)][:1]
    target=_call(connection,'Target.createTarget',{'url':IP_INFO_URL,'background':False},receipt='targetId')
    if target in before:raise _failure(ValueError(),'Target.createTarget')
    deadline=time.monotonic()+_confirmation_budget(connection)
    _confirmed(connection,target,deadline,creating=True)
    closed=[]
    for identity in previous:
        current=_confirmed(connection,target,deadline,creating=True)
        if not _info(current.get(identity)):continue
        result=_within_confirmation(connection,deadline,lambda:_call(connection,'Target.closeTarget',{'targetId':identity}))
        if result.get('success') is not True:raise _failure(ValueError(),'Target.closeTarget')
        closed.append(identity)
    _confirmed(connection,target,deadline,creating=True,closed=closed,previous=previous)
    _within_confirmation(connection,deadline,lambda:_call(connection,'Target.activateTarget',{'targetId':target}))
    return target
