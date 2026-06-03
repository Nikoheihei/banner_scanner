from .cli import main
import sys, asyncio

sys.exit(asyncio.run(main()))
