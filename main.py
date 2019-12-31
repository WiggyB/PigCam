# Extended python -m http.serve with --username and --password parameters for
# basic auth, based on https://gist.github.com/fxsjy/5465353

from functools import partial
from http.server import SimpleHTTPRequestHandler, test
import base64
import os
import io
import picamera
import logging
import socketserver
from threading import Condition
from http import server


class StreamingOutput(object):
    def __init__(self):
        self.frame = None
        self.buffer = io.BytesIO()
        self.condition = Condition()

    def write(self, buf):
        if buf.startswith(b'\xff\xd8'):
            # New frame, copy the existing buffer's content and notify all
            # clients it's available
            self.buffer.truncate()
            with self.condition:
                self.frame = self.buffer.getvalue()
                self.condition.notify_all()
            self.buffer.seek(0)
        return self.buffer.write(buf)

class StreamingServer(socketserver.ThreadingMixIn, server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    """ Main class to present webpages and authentication. """

    def __init__(self, *args, **kwargs):
        # username = kwargs.pop("username")
        # password = kwargs.pop("password")
        # self._auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._auth = base64.b64encode(f"rusty:bramble".encode()).decode()
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Test"')
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        """ Present frontpage with user authentication. """
        if self.headers.get("Authorization") == None:
            self.do_AUTHHEAD()
            self.wfile.write(b"no auth header received")
        elif self.headers.get("Authorization") == "Basic " + self._auth:
            if self.path == "/":
                print("asking for site")
                SimpleHTTPRequestHandler.do_GET(self)
                #content = PAGE.encode('utf-8')
                #self.send_response(200)
                #self.send_header('Content-Type', 'text/html')
                #self.send_header('Content-Length', len(content))
                #self.end_headers()
                #self.wfile.write(content)
            elif self.path == "/pigs.jpg":
                self.send_response(200)
                self.send_header('Content-type','image/jpg')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                with open("pigs.jpg", "rb") as fout:
                    self.wfile.write(fout.read())
            elif self.path == '/stream.mjpg':
                print("asking for stream")
                self.send_response(200)
                self.send_header('Age', 0)
                self.send_header('Cache-Control', 'no-cache, private')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Content-Type', 'multipart/x-mixed-replace; boundary=FRAME')
                self.end_headers()
                try:
                    while True:
                        with output.condition:
                            output.condition.wait()
                            frame = output.frame
                        self.wfile.write(b'--FRAME\r\n')
                        self.send_header('Content-Type', 'image/jpeg')
                        self.send_header('Content-Length', len(frame))
                        self.end_headers()
                        self.wfile.write(frame)
                        self.wfile.write(b'\r\n')
                except Exception as e:
                    logging.warning(
                        'Removed streaming client %s: %s',
                        self.client_address, str(e))
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.get("Authorization").encode())
            self.wfile.write(b"not authenticated")


if __name__ == "__main__":
    import argparse

    index = open("index.html", "r")
    PAGE = index.read()

    camera = picamera.PiCamera(resolution='640x480', framerate=24)
    output = StreamingOutput()
    #Uncomment the next line to change your Pi's Camera rotation (in degrees)
    camera.rotation = 180
    camera.start_recording(output, format='mjpeg')
    #try:
    #    address = ('', 8000)
    #    server = StreamingServer(address, StreamingHandler)
    #    server.serve_forever()

    parser = argparse.ArgumentParser()
    parser.add_argument("--cgi", action="store_true", help="Run as CGI Server")
    parser.add_argument(
        "--bind",
        "-b",
        metavar="ADDRESS",
        default="0.0.0.0",
        help="Specify alternate bind address " "[default: all interfaces]",
    )
    parser.add_argument(
        "--directory",
        "-d",
        default=os.getcwd(),
        help="Specify alternative directory " "[default:current directory]",
    )
    parser.add_argument(
        "port",
        action="store",
        default=80,
        type=int,
        nargs="?",
        help="Specify alternate port [default: 8000]",
    )
    parser.add_argument("--username", "-u", metavar="USERNAME")
    parser.add_argument("--password", "-p", metavar="PASSWORD")
    args = parser.parse_args()

    handler_class = partial(
        AuthHTTPRequestHandler,
        #username=args.username,
        #password=args.password,
        directory=args.directory,
    )
    test(HandlerClass=handler_class, port=args.port, bind=args.bind)