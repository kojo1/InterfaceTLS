import logging

logger = logging.getLogger("InterfaceTLS")  # 名前付きロガーにしておくと便利

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
