import logging
import os
import sys


class ColorFormatter(logging.Formatter):
    RESET = "\x1b[0m"
    COLORS = {
        logging.DEBUG: "\x1b[36m",
        logging.INFO: "\x1b[32m",
        logging.WARNING: "\x1b[33m",
        logging.ERROR: "\x1b[31m",
        logging.CRITICAL: "\x1b[35m",
    }

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        color = self.COLORS.get(record.levelno, "")
        if not color:
            return message
        return f"{color}{message}{self.RESET}"


class LoggerManager:
    _configured = False
    _base_logger_name = "multisource_attack_graph"

    @classmethod
    def _parse_level(cls, level: str | int | None) -> int:
        if isinstance(level, int):
            return level
        if not level:
            level = os.getenv("LOG_LEVEL", "INFO")
        return getattr(logging, str(level).upper(), logging.INFO)

    @classmethod
    def configure(cls, level: str | int | None = None, use_color: bool = True) -> None:
        base_logger = logging.getLogger(cls._base_logger_name)

        if cls._configured:
            # Do not implicitly reset to INFO when get_logger() is called.
            # Only update level when caller explicitly passes one.
            if level is not None:
                parsed_level = cls._parse_level(level)
                base_logger.setLevel(parsed_level)
                for handler in base_logger.handlers:
                    handler.setLevel(parsed_level)
            return

        parsed_level = cls._parse_level(level)

        base_logger.propagate = False
        base_logger.setLevel(parsed_level)

        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(parsed_level)
        formatter: logging.Formatter
        if use_color:
            formatter = ColorFormatter(
                "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        else:
            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        handler.setFormatter(formatter)

        base_logger.handlers.clear()
        base_logger.addHandler(handler)

        cls._configured = True

    @classmethod
    def set_level(cls, level: str | int) -> None:
        cls.configure(level=level)

    @classmethod
    def get_logger(cls, name: str | None = None) -> logging.Logger:
        cls.configure()
        if not name:
            return logging.getLogger(cls._base_logger_name)
        return logging.getLogger(f"{cls._base_logger_name}.{name}")
