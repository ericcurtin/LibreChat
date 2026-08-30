import mongoose, { Types } from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { createMethods, createModels } from '@librechat/data-schemas';
import { AccessRoleIds, PrincipalType, ResourceType } from 'librechat-data-provider';
import { AccessControlService } from '~/acl/accessControlService';
import { createCodeEnvironmentRegistry } from './environments';
import { revokeUserCodeEnvironmentWorkers } from './lifecycle';

describe('code environment registry', () => {
  let mongoServer: MongoMemoryServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    await mongoose.connect(mongoServer.getUri());
    createModels(mongoose);
    await Promise.all(Object.values(mongoose.models).map((model) => model.init()));
    await createMethods(mongoose).seedDefaultRoles();
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    await mongoose.connection.dropDatabase();
    await createMethods(mongoose).seedDefaultRoles();
  });

  test('discovers a registered environment only for its owner principal', async () => {
    const registry = createCodeEnvironmentRegistry(mongoose);
    const ownerId = new Types.ObjectId();
    const strangerId = new Types.ObjectId();

    const created = await registry.register({
      actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
      environment: {
        id: 'danny-vm',
        name: "Danny's VM",
        type: 'attached',
        baseURL: 'https://code.example.com',
        workerId: 'danny-worker',
      },
    });

    expect(created).toEqual({
      resourceId: expect.any(String),
      id: 'danny-vm',
      name: "Danny's VM",
      type: 'attached',
      canDelete: true,
    });
    await expect(
      registry.listAccessible({ userId: ownerId, role: 'USER', idOnTheSource: null }),
    ).resolves.toEqual([created]);
    await expect(
      registry.listAccessible({ userId: strangerId, role: 'USER', idOnTheSource: null }),
    ).resolves.toEqual([]);
    await expect(
      registry.listAccessibleConfigurations({
        userId: ownerId,
        role: 'USER',
        idOnTheSource: null,
      }),
    ).resolves.toEqual([
      {
        id: 'danny-vm',
        name: "Danny's VM",
        type: 'attached',
        baseURL: 'https://code.example.com',
        owner: 'principal',
        workerId: 'danny-worker',
      },
    ]);
  });

  test('discovers environments granted through role and group principals', async () => {
    const registry = createCodeEnvironmentRegistry(mongoose);
    const methods = createMethods(mongoose);
    const access = new AccessControlService(mongoose);
    const ownerId = new Types.ObjectId();
    const teammateId = new Types.ObjectId();
    const group = await methods.createGroup({
      name: 'Code Team',
      source: 'local',
      memberIds: [teammateId.toString()],
    });
    const roleEnvironment = await registry.register({
      actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
      environment: {
        id: 'role-vm',
        name: 'Role VM',
        type: 'attached',
        baseURL: 'https://code.example.com',
      },
    });
    const groupEnvironment = await registry.register({
      actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
      environment: {
        id: 'group-vm',
        name: 'Group VM',
        type: 'attached',
        baseURL: 'https://code.example.com',
      },
    });

    await access.grantPermission({
      principalType: PrincipalType.ROLE,
      principalId: 'CODE_USER',
      resourceType: ResourceType.CODE_ENVIRONMENT,
      resourceId: roleEnvironment.resourceId,
      accessRoleId: AccessRoleIds.CODE_ENVIRONMENT_VIEWER,
      grantedBy: ownerId,
    });
    await access.grantPermission({
      principalType: PrincipalType.GROUP,
      principalId: group._id,
      resourceType: ResourceType.CODE_ENVIRONMENT,
      resourceId: groupEnvironment.resourceId,
      accessRoleId: AccessRoleIds.CODE_ENVIRONMENT_VIEWER,
      grantedBy: ownerId,
    });

    await expect(
      registry.listAccessible({
        userId: teammateId,
        role: 'CODE_USER',
        idOnTheSource: null,
      }),
    ).resolves.toEqual([
      { ...roleEnvironment, canDelete: false },
      { ...groupEnvironment, canDelete: false },
    ]);
  });

  test('computes delete permissions for an environment list in one batch', async () => {
    const batchSpy = jest.spyOn(AccessControlService.prototype, 'getResourcePermissionsMap');
    const singleSpy = jest.spyOn(AccessControlService.prototype, 'checkPermission');
    const registry = createCodeEnvironmentRegistry(mongoose);
    const ownerId = new Types.ObjectId();
    for (const id of ['batch-one', 'batch-two']) {
      await registry.register({
        actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
        environment: {
          id,
          name: id,
          type: 'attached',
          baseURL: 'https://code.example.com',
        },
      });
    }

    await expect(
      registry.listAccessible({ userId: ownerId, role: 'USER', idOnTheSource: null }),
    ).resolves.toHaveLength(2);
    expect(batchSpy).toHaveBeenCalledTimes(1);
    expect(singleSpy).not.toHaveBeenCalled();

    batchSpy.mockRestore();
    singleSpy.mockRestore();
  });

  test('atomically limits concurrent environment registrations for one owner', async () => {
    await mongoose.models.CodeEnvironment.createCollection();
    await expect(mongoose.models.CodeEnvironment.collection.indexes()).resolves.toEqual([
      expect.objectContaining({ name: '_id_' }),
    ]);
    const registry = createCodeEnvironmentRegistry(mongoose);
    const ownerId = new Types.ObjectId();

    const results = await Promise.allSettled(
      ['quota-one', 'quota-two', 'quota-three'].map((id) =>
        registry.register({
          actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
          environment: {
            id,
            name: id,
            type: 'attached',
            baseURL: 'https://code.example.com',
          },
          maxOwned: 2,
        } as never),
      ),
    );

    expect(results.filter(({ status }) => status === 'fulfilled')).toHaveLength(2);
    expect(results.filter(({ status }) => status === 'rejected')).toHaveLength(1);
    expect(results.find(({ status }) => status === 'rejected')).toMatchObject({
      reason: { name: 'CodeEnvironmentLimitError' },
    });
    await expect(
      mongoose.models.CodeEnvironment.countDocuments({ createdBy: ownerId }),
    ).resolves.toBe(2);
  });

  test('keeps a user-bound worker private even if its ACL is granted to a role', async () => {
    const registry = createCodeEnvironmentRegistry(mongoose);
    const access = new AccessControlService(mongoose);
    const ownerId = new Types.ObjectId();
    const teammateId = new Types.ObjectId();
    const environment = await registry.register({
      actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
      environment: {
        id: 'owner-worker',
        name: 'Owner worker',
        type: 'attached',
        baseURL: 'https://code.example.com',
        workerId: 'owner-worker',
        workerPrincipal: { type: 'user', id: ownerId.toString() },
      },
    });
    await access.grantPermission({
      principalType: PrincipalType.ROLE,
      principalId: 'CODE_USER',
      resourceType: ResourceType.CODE_ENVIRONMENT,
      resourceId: environment.resourceId,
      accessRoleId: AccessRoleIds.CODE_ENVIRONMENT_VIEWER,
      grantedBy: ownerId,
    });

    await expect(
      registry.listAccessible({ userId: teammateId, role: 'CODE_USER', idOnTheSource: null }),
    ).resolves.toEqual([]);
    await expect(
      registry.listAccessible({ userId: ownerId, role: 'USER', idOnTheSource: null }),
    ).resolves.toEqual([environment]);
  });

  test('deletes an owner environment and its ACL after lifecycle cleanup succeeds', async () => {
    const registry = createCodeEnvironmentRegistry(mongoose);
    const ownerId = new Types.ObjectId();
    const environment = await registry.register({
      actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
      environment: {
        id: 'remove-me',
        name: 'Remove me',
        type: 'attached',
        baseURL: 'https://code.example.com',
        workerId: 'remove-me',
        controlPlaneId: 'self-service',
        workerPrincipal: { type: 'user', id: ownerId.toString() },
      },
    });
    const beforeDelete = jest.fn().mockResolvedValue(undefined);

    await expect(
      registry.remove({
        actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
        environmentId: 'remove-me',
        beforeDelete,
      }),
    ).resolves.toEqual(environment);
    expect(beforeDelete).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 'remove-me',
        workerId: 'remove-me',
        controlPlaneId: 'self-service',
      }),
    );
    await expect(
      mongoose.models.AclEntry.countDocuments({ resourceId: environment.resourceId }),
    ).resolves.toBe(0);
    await expect(
      registry.listAccessible({ userId: ownerId, role: 'USER', idOnTheSource: null }),
    ).resolves.toEqual([]);
  });

  test('fences removal while an agent write is reserving the environment', async () => {
    const registry = createCodeEnvironmentRegistry(mongoose);
    const methods = createMethods(mongoose);
    const ownerId = new Types.ObjectId();
    await registry.register({
      actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
      environment: {
        id: 'agent-write-race',
        name: 'Agent write race',
        type: 'attached',
        baseURL: 'https://code.example.com',
      },
    });
    const Agent = mongoose.models.Agent;
    const createAgent = Agent.create.bind(Agent);
    let enteredCreate!: () => void;
    let releaseCreate!: () => void;
    const entered = new Promise<void>((resolve) => (enteredCreate = resolve));
    const release = new Promise<void>((resolve) => (releaseCreate = resolve));
    const createSpy = jest.spyOn(Agent, 'create').mockImplementationOnce(async (input) => {
      enteredCreate();
      await release;
      return await createAgent(input);
    });

    const pendingAgent = methods.createAgent({
      id: 'agent_write_race',
      name: 'Agent write race',
      author: ownerId,
      model: 'test-model',
      provider: 'test-provider',
      code_environment_id: 'agent-write-race',
    });
    await entered;

    await expect(
      registry.remove({
        actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
        environmentId: 'agent-write-race',
      }),
    ).rejects.toMatchObject({ name: 'CodeEnvironmentInUseError' });

    releaseCreate();
    await expect(pendingAgent).resolves.toMatchObject({
      code_environment_id: 'agent-write-race',
    });
    createSpy.mockRestore();
  });

  test('revokes every user-bound worker before account deletion', async () => {
    const ownerId = new Types.ObjectId();
    await createCodeEnvironmentRegistry(mongoose).register({
      actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
      environment: {
        id: 'account-worker',
        name: 'Account worker',
        type: 'attached',
        baseURL: 'https://code.example.com/v1',
        workerId: 'account-worker',
        controlPlaneId: 'self-service',
        revocationTokenEnv: 'CODE_ADMIN_TOKEN',
        workerPrincipal: { type: 'user', id: ownerId.toString() },
      },
    });
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ protocolVersion: 1, revoked: true }),
    });

    await expect(
      revokeUserCodeEnvironmentWorkers({
        mongoose,
        userId: ownerId.toString(),
        appConfig: {
          endpoints: {
            agents: {
              statefulCodeSessions: {
                allowedEnvironments: ['user'],
                environments: [],
              },
            },
          },
        } as never,
        readSecret: () => 'administrator-token',
        fetchImpl,
      }),
    ).resolves.toBe(1);
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://code.example.com/v1/bridge/workers/account-worker/revoke',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  test('reports successful revocations without aborting after another worker fails', async () => {
    const ownerId = new Types.ObjectId();
    const registry = createCodeEnvironmentRegistry(mongoose);
    for (const id of ['worker-ok', 'worker-unreachable']) {
      await registry.register({
        actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
        environment: {
          id,
          name: id,
          type: 'attached',
          baseURL: `https://${id}.example.com/v1`,
          workerId: id,
          revocationTokenEnv: 'CODE_ADMIN_TOKEN',
          workerPrincipal: { type: 'user', id: ownerId.toString() },
        },
      });
    }
    const fetchImpl = jest.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.includes('unreachable')) {
        throw new Error('control plane unavailable');
      }
      return {
        ok: true,
        json: async () => ({ protocolVersion: 1, revoked: true }),
      } as Response;
    });

    await expect(
      revokeUserCodeEnvironmentWorkers({
        mongoose,
        userId: ownerId.toString(),
        appConfig: {} as never,
        readSecret: () => 'administrator-token',
        fetchImpl,
      }),
    ).resolves.toBe(1);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    await expect(createMethods(mongoose).deleteUserCodeEnvironments(ownerId)).resolves.toBe(1);
    await expect(
      mongoose.models.CodeEnvironment.findOne({ environmentId: 'worker-ok' }),
    ).resolves.toBeNull();
    await expect(
      mongoose.models.CodeEnvironment.findOne({ environmentId: 'worker-unreachable' }).lean(),
    ).resolves.toMatchObject({
      revocationPendingAt: expect.any(Date),
      revocationAttempts: 1,
      revocationLastError: 'Code bridge lifecycle request failed',
    });
  });

  test('removes creator-owned environment records and grants when the user is deleted', async () => {
    const registry = createCodeEnvironmentRegistry(mongoose);
    const methods = createMethods(mongoose);
    const ownerId = new Types.ObjectId();
    const environment = await registry.register({
      actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
      environment: {
        id: 'departing-user-vm',
        name: 'Departing user VM',
        type: 'attached',
        baseURL: 'https://code.example.com',
      },
    });

    await expect(methods.deleteUserCodeEnvironments(ownerId)).resolves.toBe(1);
    await expect(
      registry.listAccessible({ userId: ownerId, role: 'USER', idOnTheSource: null }),
    ).resolves.toEqual([]);
    await expect(
      mongoose.models.AclEntry.countDocuments({
        resourceType: ResourceType.CODE_ENVIRONMENT,
        resourceId: environment.resourceId,
      }),
    ).resolves.toBe(0);
  });

  test('preserves a creator-owned environment referenced by another surviving agent', async () => {
    const registry = createCodeEnvironmentRegistry(mongoose);
    const methods = createMethods(mongoose);
    const ownerId = new Types.ObjectId();
    const teammateId = new Types.ObjectId();
    const environment = await registry.register({
      actor: { userId: ownerId, role: 'USER', idOnTheSource: null },
      environment: {
        id: 'shared-deployment-worker',
        name: 'Shared deployment worker',
        type: 'attached',
        baseURL: 'https://code.example.com',
        workerPrincipal: { type: 'deployment', id: 'shared-control-plane' },
      },
    });
    await mongoose.models.Agent.create({
      id: 'agent_survives_owner',
      name: 'Surviving agent',
      author: teammateId,
      model: 'test-model',
      provider: 'test-provider',
      code_environment_id: environment.id,
    });

    await expect(methods.deleteUserCodeEnvironments(ownerId)).resolves.toBe(0);
    await expect(
      mongoose.models.CodeEnvironment.findOne({ environmentId: environment.id }),
    ).resolves.not.toBeNull();
    await expect(
      mongoose.models.AclEntry.countDocuments({ resourceId: environment.resourceId }),
    ).resolves.toBeGreaterThan(0);
  });
});
