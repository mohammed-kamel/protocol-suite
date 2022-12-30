import asyncio
from kademlia.network import Server

async def run():
    # Create a node and start listening on port 5678
    node = Server()
    print("New node listening")
    await node.listen(5678)

    # Bootstrap the node by connecting to other known nodes, in this case
    # replace 127.0.0.1 with the IP of another node and optionally
    # give as many ip/port combos as you can for other nodes.
    print("New node waiting for the bootstrap connection")
    await node.bootstrap([("127.0.0.1", 8468)])

    # set a value for the key "my-key" on the network
    await node.set("my-key", "my awesome value")

    # get the value associated with "my-key" from the network
    result = await node.get("my-key")
    print(result)

asyncio.run(run())