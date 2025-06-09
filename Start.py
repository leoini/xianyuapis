import os
import asyncio
from XianyuAutoAsync import XianyuLive

if __name__ == '__main__':
    cookies_str = os.getenv('COOKIES_STR')
    xianyuLive = XianyuLive(cookies_str)
    asyncio.run(xianyuLive.main()) 