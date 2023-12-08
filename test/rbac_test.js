const { ApiPromise, WsProvider } = require('@polkadot/api');
const { Keyring } = require('@polkadot/keyring');
const { CodePromise, ContractPromise } = require('@polkadot/api-contract');
const fs = require('fs');
const assert = require('assert').strict;
const yargs = require('yargs/yargs');
const { BN, BN_ONE } = require('@polkadot/util');
const { WeightV2 } = require('@polkadot/types/interfaces');

const MAX_CALL_WEIGHT = new BN(50_000_000_000).isub(BN_ONE);
const PROOFSIZE = new BN(2_000_000);

const DEFAULT_NODE_WS_URL = 'ws://127.0.0.1:10044';
const RBAC_CONTRACT_PATH = './rbac.contract';
const WAIT_TIME = 50000;


const USER_ADDRS = [
    '0x1122334455667788990011223344556677889900112233445566778899000000',
    '0x1122334455667788990011223344556677889900112233445566778899000001',
];
const GROUP_ADDRS = [
    '0x1122334455667788990011223344556677889900112233445566778899000010',
    '0x1122334455667788990011223344556677889900112233445566778899000011',
    '0x1122334455667788990011223344556677889900112233445566778899000012',
];
const ROLE_ADDRS = [
    '0x1122334455667788990011223344556677889900112233445566778899000020',
    '0x1122334455667788990011223344556677889900112233445566778899000021',
    '0x1122334455667788990011223344556677889900112233445566778899000022',
    '0x1122334455667788990011223344556677889900112233445566778899000023',
];
const PERM_ADDRS = [
    '0x1122334455667788990011223344556677889900112233445566778899000030',
    '0x1122334455667788990011223344556677889900112233445566778899000031',
    '0x1122334455667788990011223344556677889900112233445566778899000032',
    '0x1122334455667788990011223344556677889900112233445566778899000033',
    '0x1122334455667788990011223344556677889900112233445566778899000034',
];

async function main(nodeWSUrL) {
    // Initialise the provider to connect to the local node
    const provider = new WsProvider(nodeWSUrL);

    // Create the API and wait until ready
    const api = await ApiPromise.create({
        provider,
    });

    const GAS_LIMIT = {
        gasLimit: api?.registry.createType('WeightV2', {
            refTime: MAX_CALL_WEIGHT,
            proofSize: PROOFSIZE,
        }),
        storageDepositLimit: 5000000000000000,
        value: 0,
    };


    const doNothingFunc = (result) => {}; // eslint-disable-line
    async function contractTransaction(contractAPI, signer, callback = doNothingFunc) {
        await contractAPI.signAndSend(signer, (result) => {
            if (result.status.isInBlock || result.status.isFinalized) {
                callback(result);
                result.events
                    .filter(({ event }) => api.events.system.ExtrinsicFailed.is(event))
                    .forEach(({ event: { data: [error, info] } }) => {
                        if (error.isModule) {
                            console.dir(info);
                            // for module errors, we have the section indexed, lookup
                            const decoded = api.registry.findMetaError(error.asModule);
                            const { docs, method, section } = decoded;

                            console.log(`Error: ${section}.${method}: ${docs.join(' ')}`);
                        } else {
                            // Other, CannotLookup, BadOrigin, no extra info
                            console.log(`Error: ${error.toString()}`);
                        }
                        throw new Error('Tx failure');
                    });
                result.events
                    .filter(({ event }) => api.events.system.ExtrinsicSuccess.is(event))
                    .forEach((data) => {
                        console.log(`Success: ${data}`);
                    });
            }
        });
        await new Promise(resolve => setTimeout(resolve, WAIT_TIME));
    }

    const keyring = new Keyring({ type: 'sr25519' });
    const alice = keyring.addFromUri('//Alice');

    // Load contract
    const rawdata = fs.readFileSync(RBAC_CONTRACT_PATH);
    const contractData = JSON.parse(rawdata);
    const code = new CodePromise(api, contractData, contractData.source.wasm);

    // Deploy + setup blueprint
    console.log('----- Test Deploy');
    let addr;
    await contractTransaction(
        code.tx.default(GAS_LIMIT),
        alice,
        (result) => { addr = result.contract.address; },
    );

    const contract = new ContractPromise(api, contractData, addr);


    let callValue = await contract.query.checkAccess(
        alice.address,
        GAS_LIMIT,
        USER_ADDRS[1],
        PERM_ADDRS[0],
    );
    assert.equal(callValue.output.valueOf(), false);

    // User0 has Group0
    // User0 has Group1
    // User1 has nothing

    // Group0 has Role0
    // Group1 has Role1
    // User0 has Role2

    // Role0 has Perm0
    // Role0 has Perm1
    // Role1 has Perm2
    // Role2 has Perm3
    // Role3 has nothing

    console.log('----- Test addRoleToPermission');
    await contractTransaction(
        contract.tx.addUserToGroup(
            GAS_LIMIT, USER_ADDRS[0], GROUP_ADDRS[0],
        ),
        alice,
    );

    await contractTransaction(
        contract.tx.addUserToGroup(
            GAS_LIMIT, USER_ADDRS[0], GROUP_ADDRS[1],
        ),
        alice,
    );

    // Check group
    console.log('--- Test readGroup');
    // let callValue = [];
    callValue = await contract.query.readUserGroup(
        alice.address,
        GAS_LIMIT,
        GROUP_ADDRS[0],
    );
    assert.equal(callValue.output.length, 1);
    assert.equal(callValue.output[0].toHex(), USER_ADDRS[0]);

    callValue = await contract.query.readUserGroup(
        alice.address,
        GAS_LIMIT,
        GROUP_ADDRS[1],
    );
    assert.equal(callValue.output.length, 1);
    assert.equal(callValue.output[0].toHex(), USER_ADDRS[0]);

    callValue = await contract.query.readUserGroup(
        alice.address,
        GAS_LIMIT,
        GROUP_ADDRS[2],
    );
    assert.equal(callValue.output.length, 0);

    // UserGroup assign role
    await contractTransaction(
        contract.tx.addUserOrGroupToRole(
            GAS_LIMIT, GROUP_ADDRS[0], ROLE_ADDRS[0],
        ),
        alice,
    );

    await contractTransaction(
        contract.tx.addUserOrGroupToRole(
            GAS_LIMIT, GROUP_ADDRS[1], ROLE_ADDRS[1],
        ),
        alice,
    );

    await contractTransaction(
        contract.tx.addUserOrGroupToRole(
            GAS_LIMIT, USER_ADDRS[0], ROLE_ADDRS[2],
        ),
        alice,
    );

    console.log('--- Test readRole');
    // Permission exist
    // Permission ROLE_ADDRS[0] has PERM_ADDRS[0]
    callValue = await contract.query.readUserOrGroupRoles(
        alice.address,
        GAS_LIMIT,
        GROUP_ADDRS[0],
    );
    assert.equal(callValue.output.length, 1);
    assert.equal(callValue.output[0].toHex(), ROLE_ADDRS[0]);

    callValue = await contract.query.readUserOrGroupRoles(
        alice.address,
        GAS_LIMIT,
        GROUP_ADDRS[1],
    );
    assert.equal(callValue.output.length, 1);
    assert.equal(callValue.output[0].toHex(), ROLE_ADDRS[1]);

    callValue = await contract.query.readUserOrGroupRoles(
        alice.address,
        GAS_LIMIT,
        USER_ADDRS[0],
    );
    assert.equal(callValue.output.length, 3);
    callValue.output.forEach((element) => {
        assert.notEqual([ROLE_ADDRS[0], ROLE_ADDRS[1], ROLE_ADDRS[2]].indexOf(element.toHex()), -1);
    });

    console.log('----- Test addRoleToPermission');
    // Add role[0] --> perm[0]
    await contractTransaction(
        contract.tx.addRoleToPermission(
            GAS_LIMIT, ROLE_ADDRS[0], PERM_ADDRS[0],
        ),
        alice,
    );

    // Add role[0] --> perm[1]
    await contractTransaction(
        contract.tx.addRoleToPermission(
            GAS_LIMIT, ROLE_ADDRS[0], PERM_ADDRS[1],
        ),
        alice,
    );

    // Add role[1] --> perm[2]
    await contractTransaction(
        contract.tx.addRoleToPermission(
            GAS_LIMIT, ROLE_ADDRS[1], PERM_ADDRS[2],
        ),
        alice,
    );

    // Add role[2] --> perm[3]
    await contractTransaction(
        contract.tx.addRoleToPermission(
            GAS_LIMIT, ROLE_ADDRS[2], PERM_ADDRS[3],
        ),
        alice,
    );

    console.log('--- Test readPermissions');
    // Permission exist
    // Permission ROLE_ADDRS[0] has PERM_ADDRS[0]
    callValue = await contract.query.readPermissions(
        alice.address,
        GAS_LIMIT,
        ROLE_ADDRS[0],
    );
    assert.equal(callValue.output.length, 2);
    callValue.output.forEach((element) => {
        assert.notEqual([PERM_ADDRS[0], PERM_ADDRS[1]].indexOf(element.toHex()), -1);
    });

    callValue = await contract.query.readPermissions(
        alice.address,
        GAS_LIMIT,
        ROLE_ADDRS[1],
    );
    assert.equal(callValue.output.length, 1);
    assert.equal(callValue.output[0].toHex(), PERM_ADDRS[2]);

    callValue = await contract.query.readPermissions(
        alice.address,
        GAS_LIMIT,
        ROLE_ADDRS[2],
    );
    assert.equal(callValue.output.length, 1);
    assert.equal(callValue.output[0].toHex(), PERM_ADDRS[3]);

    // Permission ROLE_ADDRS[3] has no permission
    callValue = await contract.query.readPermissions(
        alice.address,
        GAS_LIMIT,
        ROLE_ADDRS[3],
    );
    assert.equal(callValue.output.length, 0);

    console.log('--- Test checkAccess');
    // Permission exist
    // Permission ROLE_ADDRS[0] has PERM_ADDRS[0]
    callValue = await contract.query.checkAccess(
        alice.address,
        GAS_LIMIT,
        USER_ADDRS[0],
        PERM_ADDRS[0],
    );
    assert.equal(callValue.output.valueOf(), true);

    callValue = await contract.query.checkAccess(
        alice.address,
        GAS_LIMIT,
        USER_ADDRS[0],
        PERM_ADDRS[1],
    );
    assert.equal(callValue.output.valueOf(), true);

    callValue = await contract.query.checkAccess(
        alice.address,
        GAS_LIMIT,
        USER_ADDRS[0],
        PERM_ADDRS[2],
    );
    assert.equal(callValue.output.valueOf(), true);

    callValue = await contract.query.checkAccess(
        alice.address,
        GAS_LIMIT,
        USER_ADDRS[0],
        PERM_ADDRS[3],
    );
    assert.equal(callValue.output.valueOf(), true);

    callValue = await contract.query.checkAccess(
        alice.address,
        GAS_LIMIT,
        USER_ADDRS[0],
        PERM_ADDRS[4],
    );
    assert.equal(callValue.output.valueOf(), false);

    callValue = await contract.query.checkAccess(
        alice.address,
        GAS_LIMIT,
        USER_ADDRS[1],
        PERM_ADDRS[0],
    );
    assert.equal(callValue.output.valueOf(), false);
    api.disconnect();
}

const { argv } = yargs(process.argv.slice(2))
    .usage('Usage: $0 --node_ws URL [options]')
    .example('$0 --node_ws wss://127.0.0.1:10044', 'Start to deploy')
    .option('node_ws', {
        describe: 'The width of the area.',
        type: 'string',
        nargs: 1,
    })
    .describe('help', 'Show help.') // Override --help usage message.
    .describe('version', 'Show version number.');

const nodeWSUrL = argv.node_ws || DEFAULT_NODE_WS_URL;

main(nodeWSUrL).catch(console.error).finally(() => process.exit());
