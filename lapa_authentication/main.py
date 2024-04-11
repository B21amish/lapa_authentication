from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from uvicorn import run

from lapa_authentication.configuration import (
    config_int_host_port,
    config_str_host_ip,
    global_object_square_logger,
    config_str_module_name
)
from lapa_authentication.routes import core, utility

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(core.router)
app.include_router(utility.router)


@app.get("/")
@global_object_square_logger.async_auto_logger
async def root():
    return JSONResponse(
        status_code=status.HTTP_200_OK, content={"text": config_str_module_name}
    )


if __name__ == "__main__":
    try:
        run(app, host=config_str_host_ip, port=config_int_host_port)

    except Exception as exc:
        global_object_square_logger.logger.critical(exc, exc_info=True)
