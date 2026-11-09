"""Open the maintained echoip service in the browser's own network context.

This uses mpolden/echoip's public deployment rather than adding a local web
server, scripts, extensions or a second browser networking stack.
"""
from local_state import LocalBrowserError

IP_INFO_URL='https://ifconfig.co/'
_INFO_URLS=frozenset((IP_INFO_URL,IP_INFO_URL.rstrip('/')))


def show_ip_info(connection):
    """Refresh one restored info tab or create one; never replace account tabs."""
    pages=connection.call('Target.getTargets').get('targetInfos',[])
    existing=next((page for page in pages if page.get('type')=='page' and page.get('url') in _INFO_URLS),None)
    if existing:
        target=existing['targetId']
        session=connection.call('Target.attachToTarget',{'targetId':target,'flatten':True})['sessionId']
        try:connection.call('Page.reload',{'ignoreCache':True},session=session)
        finally:connection.call('Target.detachFromTarget',{'sessionId':session})
    else:
        target=connection.call('Target.createTarget',{'url':IP_INFO_URL,'background':False}).get('targetId')
        if not isinstance(target,str) or not target:raise LocalBrowserError('IP信息页创建未确认。')
    connection.call('Target.activateTarget',{'targetId':target})
    return target
