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
from fractions import Fraction


class daytime_camera(object):
    def __init__(self, output):
        self.frame_rate = 24
        self.camera = picamera.PiCamera(resolution='640x480', framerate=self.frame_rate)
        self.camera.rotation = 180
        output.set_interval(self.frame_rate*600)
        self.camera.start_recording(output, format='mjpeg')

    def close(self):
        self.camera.close()


class lowlight_camera(object):
    def __init__(self, output):
        self.frame_rate = 1
        self.camera = picamera.PiCamera(resolution='640x480', framerate=self.frame_rate)
        self.camera.shutter_speed = 1000000
        self.camera.iso = 800
        self.camera.rotation = 180
        output.set_interval(self.frame_rate*600)
        self.camera.start_recording(output, format='mjpeg')

    def close(self):
        self.camera.close()

class nolight_camera(object):
    def __init__(self, output):
        self.frame_rate = Fraction(1,6)
        self.camera = picamera.PiCamera(resolution='640x480', framerate=self.frame_rate)
        self.camera.rotation = 180
        self.camera.shutter_speed = 6000000
        self.camera.iso = 800
        output.set_interval(self.frame_rate*600)
        self.camera.start_recording(output, format='mjpeg')

    def close(self):
        self.camera.close()

class StreamingOutput(object):
    def __init__(self):
        self.interval = 0
        self.frame = None
        self.buffer = io.BytesIO()
        self.condition = Condition()
        self.number = 0

    def set_interval(self, interval):
        self.interval = interval
    
    def write(self, buf):
        self.number +=1
        if self.number == self.interval:
            camera.close()
            camera = nolight_camera()
        print(type(buf))
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
    output = StreamingOutput()
    camera = daytime_camera(output)

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