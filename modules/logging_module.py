import logging
import json
import datetime


# Custom formatter for JSON logs
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.now().isoformat(),
            "level": record.levelname,
            "message": record.getMessage()
        }
        return json.dumps(log_record)


def setup_logger():
    logger = logging.getLogger("Praetorian")
    logger.setLevel(logging.DEBUG)

    # Plaintext formatter
    plain_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Console handler for real-time feedback
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(plain_formatter)

    # File handler for plaintext logs
    file_handler = logging.FileHandler("praetorian.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(plain_formatter)

    # File handler for JSON logs
    json_file_handler = logging.FileHandler("praetorian.json.log")
    json_file_handler.setLevel(logging.DEBUG)
    json_file_handler.setFormatter(JSONFormatter())

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.addHandler(json_file_handler)

    return logger


logger = setup_logger()


def log_event(level, message):
    """Log an event with the specified level and message."""
    level = level.lower()
    if level == "info":
        logger.info(message)
    elif level == "warning":
        logger.warning(message)
    elif level == "error":
        logger.error(message)
    else:
        logger.debug(message)


if __name__ == "__main__":
    log_event("info", "Logging module initialized.")
