import logging
import os

import fire


class Server(object):
    def __init__(self) -> None:
        self.config = {
            "LISTEN_HOST": os.getenv("SS_LISTEN_HOST", "0.0.0.0"),
            "SENTRY_DSN": os.getenv("SS_SENTRY_DSN"),
            "API_ENDPOINT": os.getenv("SS_API_ENDPOINT"),
            "LOG_LEVEL": os.getenv("SS_LOG_LEVEL", "info"),
            "SYNC_TIME": int(os.getenv("SS_SYNC_TIME", 60)),
            "STREAM_DNS_SERVER": os.getenv("SS_STREAM_DNS_SERVER"),
            "TIME_OUT_LIMIT": int(os.getenv("SS_TIME_OUT_LIMIT", 60)),
            "USER_TCP_CONN_LIMIT": int(os.getenv("SS_TCP_CONN_LIMIT", 60)),
        }
        self.log_level = self.config["LOG_LEVEL"]

    def __init_config(self) -> None:
        pass

    def __prepare_logger(self):
        """
        初始化日志类
        :return:
        """
        log_levels = {
            "CRITICAL": logging.CRITICAL,
            "ERROR": logging.ERROR,
            "WARNING": logging.WARNING,
            "INFO": logging.INFO,
            "DEBUG": logging.DEBUG,
        }
        level = log_levels[self.log_level.upper()]
        logging.basicConfig(
            format="[%(levelname)s]%(asctime)s %(funcName)s line:%(lineno)d %(message)s", level=level,
        )


def main():
    fire.Fire(Server)


if __name__ == "__main__":
    main()
