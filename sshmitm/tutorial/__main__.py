"""SSH-MITM Tutorial — run with: python -m sshmitm.tutorial"""

from sshmitm.tutorial._app import TutorialApp
from sshmitm.tutorial.tutorials import ALL_TUTORIALS


def main() -> None:
    TutorialApp(ALL_TUTORIALS).run()


if __name__ == "__main__":
    main()
