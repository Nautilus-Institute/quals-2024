import os

from flask import Flask

app = None


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "dummysecretdummysecretdummysecret"),
        DATABASE=os.path.join(app.instance_path, "amib_log.sqlite"),
    )

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    from . import code_serve
    app.register_blueprint(code_serve.bp)

    return app
