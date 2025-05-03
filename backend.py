from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def backend():
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Backend Response</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #e0f7fa;
                padding: 2rem;
            }}
            h2 {{
                color: #2e7d32;
                font-size: 1.5rem;
            }}
        </style>
    </head>
    <body>
        <h2> Backend Response! Method: {request.method}</h2>
    </body>
    </html>
    """, 200, {'Content-Type': 'text/html'}

if __name__ == '__main__':
    app.run(port=8000)
