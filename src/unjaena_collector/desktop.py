from unjaena_collector.privileges import relaunch_if_needed
from unjaena_collector.gui import main


if __name__ == "__main__":
    if relaunch_if_needed():
        raise SystemExit(0)
    raise SystemExit(main())
