"""Flask CLI commands."""
import sys

import pytest
import click
from flask.cli import FlaskGroup

from app.main import create_app

cli = FlaskGroup(create_app=create_app)


@cli.command("test")
@click.option("--base", help="Folder from which to run tests.")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Output verbose testing information.",
)
def run_tests(base, verbose):
    options = ["-x"]
    directory = f"app/test/{base}" if base is not None else "app/test"
    options.append(directory)
    if verbose:
        options.append("-v")
    result = pytest.main(options)
    if result == pytest.ExitCode.OK:
        return 0
    sys.exit(result.value)


@cli.command("initialize")
def initialize():
    """Initialize application."""
    from app.main.extensions import db
    from app.main.api.user import models  # noqa

    db.create_all()


@cli.command("create-operator")
@click.option("-u", "--username", required=True, help="operator username")
@click.option("-e", "--email", required=True, help="operator email address")
@click.option("-p", "--password", required=True, help="operator password")
def create_operator(username, email, password):
    from app.main.api.user.models import User
    from app.main.api.user.enum import Role

    try:
        User.create(
            username=username,
            email=email,
            password=password,
            role=Role.OPERATOR,
            active=True,
        )
    except Exception as error:
        click.echo("Something went wrong!")
        click.echo(str(error))


if __name__ == "__main__":
    cli()
