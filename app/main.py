from flask import Flask
from flask import request,render_template, flash, redirect

from werkzeug.utils import secure_filename
import os
import stat
from hashlib import sha256
from string import printable
import random
import time
from subprocess import Popen, PIPE

ALLOWED_EXTENSIONS = set(['html'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def filter_template(template_string):
	white_list = ["[]", "''", '""', "{}", "read", "write", "communicate", "base", "getitem"]            # prevent something like [].__class__ , "".__class__ which are common in SSTI attack :)
	for char in white_list:
		if char in template_string.lower():
			return char, False
	return None,True

app = Flask(__name__)

UPLOAD_FOLDER = "/var/tmp/bin"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024


@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
	return render_template('500.html'), 500



@app.route('/')
def index():
	message="Nothing to show"
	return render_template("index.html",message=message)

@app.route('/elfanalysis',methods=['GET', 'POST'])
def elfanalysis():
	message = ""
	if request.method == 'POST':
		if 'file' not in request.files:
			message = 'No file part'
			return render_template('index.html', message=message)
		file = request.files['file']

		if file.filename == '':
			message = 'No file selected for uploading'
			return render_template('upload.html', message=markdown(message, fenced_code=True))



		filename = sha256(''.join([random.choice(printable) for n in xrange(4)]) + file.filename).hexdigest() +"_"+ secure_filename(file.filename)
		filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
		
		file.save(filepath)
		os.chmod(filepath,0o777)
		print "CHMOD" +oct(os.stat(filepath)[stat.ST_MODE])
		process = Popen(["/app/chall", filepath], stdout=PIPE)
		(output, err) = process.communicate()
		exit_code = process.wait()
		
		message = output
		html_template="""
<!DOCTYPE html>
<html lang="en">
<head>
  <title>Bootstrap Example</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
  <link rel="stylesheet" type="text/css" href="//fonts.googleapis.com/css?family=Ubuntu+Mono" />
</head>
<style>
	span { font-family: "Ubuntu Mono"; font-size: 14px; font-style: normal; font-variant: normal; font-weight: 400; line-height: 20px; }
	.red{
		color:red;
	}
	.black{
		color:black;
	}
	.green{
		color:green;
	}
	.yellow{
		color:yellow;
	}
	.blue{
		color:blue;
	}
	.magneta{
		color:magneta;
	}
	.cyan{
		color:cyan;
	}
	.white{
		color:white;
	}

	.bred{
		color:red;
		font-weight: bold;
	}
	.bblack{
		color:black;
		font-weight: bold;
	}
	.bgreen{
		color:green;
		font-weight: bold;
	}
	.byellow{
		color:yellow;
		font-weight: bold;
	}
	.bblue{
		color:blue;
		font-weight: bold;
	}
	.bmagneta{
		color:magneta;
		font-weight: bold;
	}
	.bcyan{
		color:cyan;
		font-weight: bold;
	}
	.bwhite{
		color:white;
		font-weight: bold;
	}
.button {
  background-color: #f4511e;
  border: none;
  color: white;
  padding: 16px 32px;
  text-align: center;
  font-size: 16px;
  margin: 4px 2px;
  opacity: 0.6;
  transition: 0.3s;
  display: inline-block;
  text-decoration: none;
  cursor: pointer;
}

.button:hover {opacity: 1}
</style>

<body style="background-color: #2d0922 " >
<div class="container mt-3" style="color: white; margin-top:100px !important ">
<span style = "color:LimeGreen;font-size: 20px; font-weight: bold">root@fuctf</span>
:
<span style = "color:SteelBlue;font-size: 20px; font-weight: bold">~/fptu/elf_analyser</span>
$ /app/chall """+filepath+"""
		"""+output+"""
</div>
		"""
		os.remove(filepath)
		return html_template

if __name__ == "__main__":
	app.run(host='0.0.0.0',port=80,debug=True)
