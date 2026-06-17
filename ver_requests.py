import asyncio
import aiosqlite

async def ver():
    async with aiosqlite.connect('hawk.db') as db:
        async with db.execute('SELECT method, url, body FROM http_requests ORDER BY timestamp DESC LIMIT 20') as cursor:
            rows = await cursor.fetchall()
            for r in rows:
                print(r[0], r[1][:120])
                if r[2]:
                    print('  BODY:', r[2][:100])

asyncio.run(ver())