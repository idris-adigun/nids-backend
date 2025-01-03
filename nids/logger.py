import logging
import sys
import config.env as env

# Logging config
logger = logging.getLogger(__name__)

stdout_log_formatter = logging.Formatter(
    '%(asctime)s | %(levelname)s | %(message)s'
)

stdout_log_handler = logging.StreamHandler(stream=sys.stdout)
stdout_log_handler.setLevel(logging.INFO)
stdout_log_handler.setFormatter(stdout_log_formatter)

logger.addHandler(stdout_log_handler)
log_level = env.log_level
if log_level == 'DEBUG':
    logger.setLevel(logging.DEBUG)
elif log_level == 'INFO':   
    logger.setLevel(logging.INFO)
elif log_level:
    logger.setLevel(logging.WARNING)

def logInfo(message):
    logger.info(f'{message}')

def logDebug(message):
    logger.debug(f'{message}')
    
def logWarning(message):
    logger.warning(f'{message}')
    
def logError(message):
    logger.error(f'{message}')
    
def logCritical(message):
    logger.critical(f'{message}')