from string import Template
import webbrowser
from flask import Flask
from flask_cors import CORS
import threading
import sys

## create Flask app
app = Flask(__name__)
CORS(app)

server = None
contents = ""

@app.route('/', methods=['GET'])
def index():
    return contents

class server_thread_wrapper(threading.Thread): 
    def __init__(self, *args, **keywords): 
        threading.Thread.__init__(self, *args, **keywords) 
        self.killed = False

    def start(self): 
        self.__run_backup = self.run 
        self.run = self.__run       
        threading.Thread.start(self) 
  
    def __run(self): 
        sys.settrace(self.globaltrace) 
        self.__run_backup() 
        self.run = self.__run_backup 
    
    def globaltrace(self, frame, event, arg): 
        if event == 'call': 
            return self.localtrace 
        else: 
            return None
    
    def localtrace(self, frame, event, arg): 
        if self.killed: 
            if event == 'line': 
                raise SystemExit() 
        return self.localtrace 
    
    def kill(self): 
        self.killed = True

def start_server():
    global server
    server = server_thread_wrapper(target=app.run)
    server.start()
    return server

def kill_server():
    global server
    server.kill()
    server.join()

def open_duo_web(stateToken, script, host, signature, callback):
    global contents
    template = Template("""
        <!--
            The Duo SDK will automatically bind to this iFrame and populate it for us.
            See https://www.duosecurity.com/docs/duoweb for more info.
        -->
        <iframe id="duo_iframe" width="620" height="330" frameborder="0"></iframe>
        <!--
            The Duo SDK will automatically bind to this form and submit it for us.
            See https://www.duosecurity.com/docs/duoweb for more info.
        -->
        <form method="POST" id="duo_form">
            <!-- The state token is required here (in order to bind anonymous request back into Auth API) -->
            <input type="hidden" name="stateToken" value='$stateToken' />
        </form>

        <script src="$script"></script>

        <!-- The host, sig_request, and post_action values will be given via the Auth API -->
        <script>
            Duo.init({
                'host': '$host',
                'sig_request': '$signature',
                'post_action': '$callback',
                'submit_callback': function (form) {
                    fetch(form.action, {
                        method: form.method,
                        body: new FormData(form),
                    });
                    document.querySelector("body").innerHTML = "Completed. Please close window.";
                }
            });
        </script>
    """)
    contents = template.substitute(stateToken=stateToken, script=script, host=host, signature=signature, callback=callback)
    start_server()
    webbrowser.open_new("http://localhost:5000")
