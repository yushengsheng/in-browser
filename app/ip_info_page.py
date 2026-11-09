"""Open the maintained echoip service in the browser's own network context.

This uses mpolden/echoip's public deployment rather than adding a local web
server, scripts, extensions or a second browser networking stack.
"""
from local_state import LocalBrowserError

IP_INFO_URL='https://ifconfig.co/'
_INFO_URLS=frozenset((IP_INFO_URL,IP_INFO_URL.rstrip('/')))
IP_INFO_OPERATIONS=frozenset(('Target.getTargets','Target.attachToTarget','Page.reload',
    'Target.detachFromTarget','Target.createTarget','Target.activateTarget'))
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
        if receipt:
            value=result.get(receipt)
            if not isinstance(value,str) or not value:raise ValueError()
            return value
        return result
    except Exception as error:
        raise _failure(error,operation) from None


def show_ip_info(connection):
    """Refresh one restored info tab or create one; never replace account tabs."""
    pages=_call(connection,'Target.getTargets').get('targetInfos',[])
    existing=next((page for page in pages if page.get('type')=='page' and page.get('url') in _INFO_URLS),None)
    if existing:
        target=existing['targetId']
        session=_call(connection,'Target.attachToTarget',{'targetId':target,'flatten':True},receipt='sessionId')
        try:_call(connection,'Page.reload',{'ignoreCache':True},session=session)
        except Exception as error:
            try:_call(connection,'Target.detachFromTarget',{'sessionId':session})
            except Exception:error.cleanup_failed=True
            raise
        else:_call(connection,'Target.detachFromTarget',{'sessionId':session})
    else:
        target=_call(connection,'Target.createTarget',{'url':IP_INFO_URL,'background':False},receipt='targetId')
    _call(connection,'Target.activateTarget',{'targetId':target})
    return target
