import asyncio
import aiosqlite

async def ver():
    async with aiosqlite.connect('hawk.db') as db:
        async with db.execute("""
            SELECT method, url, body 
            FROM http_requests 
            WHERE url LIKE '%gruyere%' 
            ORDER BY timestamp DESC 
            LIMIT 20
        """) as cursor:
            rows = await cursor.fetchall()
            print(f"Total requisicoes Gruyere: {len(rows)}")
            for r in rows:
                print(f"\n{r[0]} {r[1][:150]}")
                if r[2]:
                    print(f"  BODY: {r[2][:200]}")

asyncio.run(ver())
