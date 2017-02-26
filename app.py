import os,requests,json

from flask import Flask
from flask import render_template
from flask import jsonify

from flask_socketio import SocketIO,emit


app = Flask(__name__)

socketio = SocketIO(app)

@app.route("/")
def index():
	return render_template("index.html",title="Home")

@app.route("/chat",methods=['GET'])
def chat():
    return render_template("chat.html")

@socketio.on('my event', namespace='/test')
def test_message(message):
    
    print message['data']

    message_text = message['data']
    server_url = "https://ccbserver.herokuapp.com/api/msg/"

    final_url = server_url+message_text
    resp = requests.get(final_url)
    msg = json.loads(resp.text)
    bot_response = msg['response'][0]['output']
	    
    # checking if a matched response is found.
    if not bot_response:
        bot_response = "error"

    print bot_response

    emit('my response', {'data': bot_response})

@socketio.on('connect', namespace='/test')
def test_connect():
    emit('my response', {'data': 'Connected'})

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    print('Client disconnected')


if __name__ == "__main__":
	port = int(os.environ.get('PORT', 5555))
	socketio.run(app, debug=True)