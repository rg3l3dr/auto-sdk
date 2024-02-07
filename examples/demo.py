from auto.entities import Registrar, Controller, Agent
import asyncio

async def run():

    # Setup Abe, the honest broker who will register certificates on behalf of entities. In practice, Abe would be an automated service run by autonomys. Any entity may still submit their own certs to the registry, but they need a blockchain wallet to do so
    abe = Registrar('Abe')

    # Setup Alice, a human who will self-issue her own certificate and register it with Abe 
    alice = Controller('Alice', abe)
    alice_cert = alice.self_register()

    # Setup Alice's agent, who wiil create a certificate signing request (CSR) for Alice and register the signed certificate with Abe. Alice' will implicitly trust Alice, since Alice signed its certificate. 
    alice_prime = Agent("Alice'", alice_cert, abe)
    await alice_prime.api.start_server()
    await alice_prime.rpc.start_service()
    alice_prime.create_csr()
    alice_prime_csr = alice.long_poll_for_agent_csr()
    alice_prime_cert = alice.sign_csr(alice_prime_csr)
    alice.save_and_trust_certificate(alice_prime_cert)
    alice.post_signed_cert_to_agent(alice_prime_cert)
    alice_prime.register(alice_prime_cert)
    await alice.rpc.connect("Alice'", alice_prime.rpc.uri)

    # Setup Bob, a human who will self-issue his own certificate and register it with Abe
    bob = Controller('Bob', abe)
    bob_cert = bob.self_register()

    # Setup Bob's agent, who wiil request a certificate from Bob and register it with Abe
    bob_prime = Agent("Bob'", bob_cert, abe)
    await bob_prime.api.start_server()
    await bob_prime.rpc.start_service()
    bob_prime.create_csr()
    bob_prime_csr = bob.long_poll_for_agent_csr()
    bob_prime_cert = bob.sign_csr(bob_prime_csr)
    bob.save_and_trust_certificate(bob_prime_cert)
    bob.post_signed_cert_to_agent(bob_prime_cert)
    bob_prime.register(bob_prime_cert)
    await bob.rpc.connect("Bob'", bob_prime.rpc.uri)

    # Connect Alice's agent to Bob's agent
    await alice.rpc.invite
    await alice_prime.api.invite_agent(alice_cert, alice_prime_cert)
    await bob.accept_invitation(bob_prime_cert, bob_cert)
    await alice_prime.rpc.connect_to_wss("Bob'")
    response = await alice_prime.send("Bob'", "Hello, Bob!")
    print(response)


