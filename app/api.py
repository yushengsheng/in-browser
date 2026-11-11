"""Public bridge action dispatch; use cases remain in ManagerService."""
from local_state import LocalBrowserError
from profile_model import sanitize
from proxy_config import parse_proxy


def dispatch(service,action,payload=None):
    payload=payload or {}
    try:
        if action=='bootstrap': result=service.bootstrap()
        elif action=='list': result=service.listing()
        elif action=='status': result=service.statuses()
        elif action=='sync_preview':result=service.synchronizer().preview()
        elif action=='sync_windows':result=service.synchronizer().start(payload.get('source_keys'),preview_id=payload.get('preview_id'))
        elif action=='sync_status':result=service.synchronizer().status(payload['job_id'],after=payload.get('after'),missing_ok=payload.get('missing_ok') is True)
        elif action=='cancel_sync':result=service.synchronizer().cancel(payload['job_id'])
        elif action=='resume_sync':result=service.synchronizer().resume(payload['job_id'])
        elif action=='creation_options':result=service.creator().options()
        elif action=='create_windows':result=service.creator().start(payload)
        elif action=='creation_status':result=service.creator().status(payload['job_id'],missing_ok=payload.get('missing_ok') is True)
        elif action=='cancel_creation':result=service.creator().cancel(payload['job_id'])
        elif action=='resume_creation':result=service.creator().resume(payload['job_id'])
        elif action=='creation_randomize':
            from creation_fingerprint import random_fingerprint
            result={'fingerprint':random_fingerprint(sanitize({'fingerprint':payload.get('fingerprint') or {}})['fingerprint'])}
        elif action=='detail': result=service.detail(payload['id'])
        elif action=='save': result=service.save(payload['profile'],allow_fingerprint=False)
        elif action=='proxy_test': result=service.configuration.proxy_test(sanitize({'proxy':payload['proxy']})['proxy'])
        elif action=='proxy_parse': result=parse_proxy(payload.get('text',''),payload.get('default_type','socks5'))
        elif action=='open': result=service.open(payload['id'])
        elif action=='close': result=service.close(payload['id'])
        elif action=='activate': result=service.activate(payload['id'])
        elif action=='delete': result=service.delete(payload['id'])
        elif action=='archive': result=service.archive(payload['id'])
        elif action=='restore': result=service.archive(payload['id'],True)
        elif action=='batch':
            errors=[]; completed=0
            if payload.get('action') not in ['open','close','archive','delete']: raise LocalBrowserError('不支持此批量操作。')
            selected=list(dict.fromkeys(payload.get('ids') or []))[:100]
            if payload['action']=='delete':
                try:
                    data=service.delete_many(selected)
                    results=[{'id':identity,'ok':True,'data':data} for identity in selected]
                    completed=len(selected) if data.get('deleted') is True and data.get('cleanup_complete') is True else 0
                    if not completed:errors=[{'id':identity,'error':data.get('message') or '永久删除尚未完成，请重试或重启继续清理。'} for identity in selected]
                except Exception as exc:
                    message=str(exc) if isinstance(exc,LocalBrowserError) else '永久删除尚未完成，部分资料可能已清理；请重试或重启继续清理。'
                    errors=[{'id':identity,'error':message} for identity in selected]
                    results=[{'id':identity,'ok':False,'error':message} for identity in selected]
                result={'completed':completed,'errors':errors,'results':results}
            else:
                for identity in selected:
                    reply=service.request(payload['action'],{'id':identity})
                    if reply['ok']: completed+=1
                    else: errors.append({'id':identity,'error':reply['error']})
                result={'completed':completed,'errors':errors}
        elif action=='groups_save': result=service.groups_save(payload)
        elif action=='settings_get': result=service.settings()
        elif action=='settings_save': result=service.save_settings(payload.get('settings',payload))
        elif action in ['choose_folder','choose_file']:
            import webview
            if not service.window: raise LocalBrowserError('请在桌面窗口选择文件。')
            chosen=service.window.create_file_dialog(webview.FileDialog.FOLDER if action=='choose_folder' else webview.FileDialog.OPEN)
            result={'path':chosen[0] if chosen else ''}
        elif action=='export_profiles': result=service.export_profiles(payload)
        elif action=='window_control':
            if service.window:
                name=payload.get('action')
                if name in ['minimize','maximize','restore','destroy']: getattr(service.window,name)()
            result={}
        else: raise LocalBrowserError('此操作尚未支持。')
        return {'ok':True,'data':result}
    except LocalBrowserError as exc: return {'ok':False,'error':str(exc)}
    except Exception:
        message='永久删除尚未完成，部分资料可能已清理；请重试或重启继续清理。' if action=='delete' or action=='batch' and payload.get('action')=='delete' else '操作未完成，原有资料和配置已保留。请检查网络、文件占用或输入内容。'
        return {'ok':False,'error':message}
