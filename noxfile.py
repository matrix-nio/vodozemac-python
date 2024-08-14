import nox


@nox.session(python=["3.9", "3.10", "3.11", "3.12"])
def test(session):
    session.install("-rrequirements-dev.txt")
    session.install("-e", ".", "--no-build-isolation")
    session.run("pytest")
