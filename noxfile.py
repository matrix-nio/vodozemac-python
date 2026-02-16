import nox_uv
from nox import Session, options

options.default_venv_backend = "uv"

@nox_uv.session(
    python=["3.10", "3.11", "3.12", "3.13", "3.14"],
    uv_groups=["tests"],
)
def test(session: Session):
    session.run("pytest")
