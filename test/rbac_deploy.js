const { ApiPromise, WsProvider } = require('@polkadot/api');
const { Keyring } = require('@polkadot/keyring');
const { CodePromise, ContractPromise } = require('@polkadot/api-contract');
const fs = require('fs');
const assert = require('assert').strict;
const yargs = require('yargs/yargs');

const DEFAULT_NODE_WS_URL = 'ws://127.0.0.1:9944';
const RBAC_CONTRACT_PATH = '../target/ink/rbac.contract';
const WAIT_TIME = 13000;

const GROUPS = {
    PeaqOffice: '0x1122334455667788990011223344556677889900112233445566778899000010',
};

const EMPLOYEES = {
    Tanisha: '0x1122334455667788990011223344556677889900112233445566778899000000',
    Leo: '0x1122334455667788990011223344556677889900112233445566778899000001',
    Anton: '0x1122334455667788990011223344556677889900112233445566778899000002',
    Maryna: '0x1122334455667788990011223344556677889900112233445566778899000003',
};

const ROLES = {
    AccessToOffice: '0x1122334455667788990011223344556677889900112233445566778899000020',
};

const PERMS = {
    GrantMainDoorUnlock: '0x1122334455667788990011223344556677889900112233445566778899000031',
};

async function main(nodeWSUrL) {
    // Initialise the provider to connect to the local node
    const provider = new WsProvider(nodeWSUrL);

    // Create the API and wait until ready
    const api = await ApiPromise.create({
        provider,
    });

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
    console.log('----- Deploy new smart contract');
    let addr;
    await contractTransaction(
        code.tx.default({ gasLimit: 100000 * 1000000 }),
        alice,
        (result) => { addr = result.contract.address; },
    );

    const contract = new ContractPromise(api, contractData, addr);

    await contractTransaction(
        contract.tx.addUserToGroup(
            { value: 0, gasLimit: 100000 * 1000000 },
            EMPLOYEES.Tanisha, GROUPS.PeaqOffice,
        ),
        alice,
    );

    await contractTransaction(
        contract.tx.addUserToGroup(
            { value: 0, gasLimit: 100000 * 1000000 },
            EMPLOYEES.Anton, GROUPS.PeaqOffice,
        ),
        alice,
    );

    // Check group
    let callValue = [];
    callValue = await contract.query.readUserGroup(
        alice.address,
        { value: 0, gasLimit: -1 },
        GROUPS.PeaqOffice,
    );
    assert.equal(callValue.output.length, 2);
    callValue.output.forEach((element) => {
        assert.notEqual([EMPLOYEES.Tanisha, EMPLOYEES.Anton].indexOf(element.toHex()), -1);
    });

    // UserGroup assign role
    await contractTransaction(
        contract.tx.addUserOrGroupToRole(
            { value: 0, gasLimit: 100000 * 1000000 },
            GROUPS.PeaqOffice, ROLES.AccessToOffice,
        ),
        alice,
    );

    await contractTransaction(
        contract.tx.addUserOrGroupToRole(
            { value: 0, gasLimit: 100000 * 1000000 },
            EMPLOYEES.Leo, ROLES.AccessToOffice,
        ),
        alice,
    );

    [GROUPS.PeaqOffice, EMPLOYEES.Leo].forEach(async (userGroup) => {
        callValue = await contract.query.readUserOrGroupRoles(
            alice.address,
            { value: 0, gasLimit: -1 },
            userGroup,
        );
        assert.equal(callValue.output.length, 1);
        assert.equal(callValue.output[0].toHex(), ROLES.AccessToOffice);
    });

    // Assign Perm
    await contractTransaction(
        contract.tx.addRoleToPermission(
            { value: 0, gasLimit: 100000 * 1000000 },
            ROLES.AccessToOffice, PERMS.GrantMainDoorUnlock,
        ),
        alice,
    );

    callValue = await contract.query.readPermissions(
        alice.address,
        { value: 0, gasLimit: -1 },
        ROLES.AccessToOffice,
    );
    assert.equal(callValue.output.length, 1);
    assert.equal(callValue.output[0].toHex(), PERMS.GrantMainDoorUnlock);

    // Checking
    [EMPLOYEES.Tanisha, EMPLOYEES.Anton, EMPLOYEES.Leo].forEach(async (employee) => {
        callValue = await contract.query.checkAccess(
            alice.address,
            { value: 0, gasLimit: -1 },
            employee,
            PERMS.GrantMainDoorUnlock,
        );
        assert.equal(callValue.output.valueOf(), true);
    });

    callValue = await contract.query.checkAccess(
        alice.address,
        { value: 0, gasLimit: -1 },
        EMPLOYEES.Maryna,
        PERMS.GrantMainDoorUnlock,
    );
    assert.equal(callValue.output.valueOf(), false);

    console.log(`---------------- Contract address: ${addr.toString()} ------------------`);
}


const { argv } = yargs(process.argv.slice(2))
    .usage('Usage: $0 --node_ws URL [options]')
    .example('$0 --node_ws wss://127.0.0.1:9944', 'Start to deploy')
    .option('node_ws', {
        describe: 'The width of the area.',
        type: 'string',
        nargs: 1,
    })
    .describe('help', 'Show help.') // Override --help usage message.
    .describe('version', 'Show version number.');

const nodeWSUrL = argv.node_ws || DEFAULT_NODE_WS_URL;

main(nodeWSUrL).catch(console.error).finally(() => process.exit());
