"""
Test Web server for making requests to
"""

from flask import Flask, jsonify, Response

from config import Config


def create_app() -> Flask:
    """
    Creates a Flask app instance and returns it

    Returns:
        Flask: Flask application
    """
    flask_app = Flask(__name__)
    app_config = Config()
    flask_app.config.from_object(app_config)

    @flask_app.after_request
    def _(response: Response) -> Response:
        """
        Sets additional secure HTTP headers in request
        responses

        Args:
            response (Response): HTTP response
        Returns:
            Response: The response to a request
        """
        default = "default-src 'self'; "
        script = "script-src 'self' 'unsafe-inline'; "
        style = "style-src 'self' 'unsafe-inline';"
        response.headers['Content-Security-Policy'] = default + script + style
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        return response

    return flask_app


app = create_app()


@app.route("/")
def index() -> Response:
    """
    Return a simple JSON response to get headers from

    Returns:
        Response: Response obj
    """
    return jsonify({"result": "success"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
