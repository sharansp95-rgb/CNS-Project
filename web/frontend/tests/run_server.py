"""Throwaway shared TLS/WS E2E server and a real Python chat peer."""
import os
from pathlib import Path
import sys
import tempfile
import threading
sys.path.insert(0,str(Path(__file__).resolve().parents[3]))
with tempfile.TemporaryDirectory(prefix='cns-browser-e2e-') as root:
    os.environ['TSA_KEY_PATH']=str(Path(root)/'tsa.key')
    os.environ['DATABASE_URL']='sqlite:///'+str(Path(root)/'chat.db')
    port=int(os.environ.get('CNS_TEST_PORT','8765'))
    os.environ['SECURECHAT_ALLOWED_ORIGINS']=f'http://127.0.0.1:{port}'
    os.environ['SECURECHAT_CERT_DIR']=root
    import uvicorn
    import certs.generate_certs as certs
    certs.KEY_PATH=str(Path(root)/'server.key')
    certs.CERT_PATH=str(Path(root)/'server.crt')
    certs.generate(force=True)
    import server.server as sm
    from server.security_log import log_event
    sm.log_event=lambda event,**fields:log_event(event,path=str(Path(root)/'security_events.jsonl'),**fields)
    from web.app import create_app
    from client.client import SecureChatClient,connect_tls
    from crypto_engine.signatures import generate_keypair,serialize_public_key
    relay=sm.ChatServer('127.0.0.1',0)
    relay.listen()
    thread=threading.Thread(target=relay.serve_forever,daemon=True)
    thread.start()
    bot=None
    def reply(kind,data):
        if kind=='message_received':
            bot.send_message('Python reply: '+data['message'])
    bot=SecureChatClient(connect_tls('127.0.0.1',relay.port),username='a_python',peer='z_browser',event_callback=reply)
    threading.Thread(target=bot.receive_loop,daemon=True).start()
    private,public=generate_keypair()
    bot.rsa_private_key=private
    bot.register('a_python','Python-bot-test-password',public_key_pem=serialize_public_key(public).decode())
    assert bot.auth_results.get(timeout=10)['success']
    try:
        uvicorn.run(create_app(relay),host='127.0.0.1',port=port,log_level='warning')
    finally:
        bot.stop_event.set()
        bot.sock.close()
        relay.shutdown()
        thread.join(timeout=5)
