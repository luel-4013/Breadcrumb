import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "app.main:app",
        host=os.environ.get("BREADCRUMB_HOST", "127.0.0.1"),
        port=int(os.environ.get("BREADCRUMB_PORT", "8787")),
        reload=os.environ.get("BREADCRUMB_RELOAD", "1") == "1",
    )


if __name__ == "__main__":
    main()
