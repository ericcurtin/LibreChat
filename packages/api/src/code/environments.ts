import { Types } from 'mongoose';
import { createMethods, logger } from '@librechat/data-schemas';
import {
  AccessRoleIds,
  PermissionBits,
  PrincipalType,
  ResourceType,
  isSecureCodeEnvironmentControlURL,
} from 'librechat-data-provider';
import { AccessControlService } from '~/acl/accessControlService';

export type CodeEnvironmentPrincipalContext = {
  userId: string | Types.ObjectId;
  role?: string | null;
  idOnTheSource?: string | null;
};

export type CodeEnvironmentSummary = {
  resourceId: string;
  id: string;
  name: string;
  type: 'managed' | 'attached';
  canDelete: boolean;
};

export type CodeEnvironmentRegistration = {
  id: string;
  name: string;
  type: 'managed' | 'attached';
  baseURL: string;
  workerId?: string;
  controlPlaneId?: string;
  revocationTokenEnv?: string;
  workerPrincipal?: {
    type: 'deployment' | 'tenant' | 'user' | 'role' | 'group';
    id: string;
  };
};

export type AccessibleCodeEnvironmentConfiguration = {
  id: string;
  name: string;
  type: 'managed' | 'attached';
  baseURL: string;
  owner: 'principal';
  workerId?: string;
};

export type CodeEnvironmentLifecycleTarget = CodeEnvironmentSummary & {
  baseURL: string;
  workerId?: string;
  controlPlaneId?: string;
  revocationTokenEnv?: string;
  workerPrincipal?: CodeEnvironmentRegistration['workerPrincipal'];
};

const ENVIRONMENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const WORKER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const WORKER_PRINCIPAL_ID_PATTERN = /^\S(?:.{0,254}\S)?$/;

export function normalizeCodeEnvironmentName(input: string): string {
  const name = input.trim();
  if (name.length < 1 || name.length > 100) {
    throw new Error('Code environment name must contain between 1 and 100 characters');
  }
  return name;
}

export class CodeEnvironmentValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CodeEnvironmentValidationError';
  }
}

export class CodeEnvironmentLimitError extends Error {
  constructor() {
    super('Personal code environment limit reached');
    this.name = 'CodeEnvironmentLimitError';
  }
}

function normalizeRegistration(input: CodeEnvironmentRegistration): CodeEnvironmentRegistration {
  const id = input.id.trim();
  const name = normalizeCodeEnvironmentName(input.name);
  const baseURL = input.baseURL.trim().replace(/\/+$/, '');
  const workerId = input.workerId?.trim();
  if (!ENVIRONMENT_ID_PATTERN.test(id)) {
    throw new CodeEnvironmentValidationError('Code environment id is invalid');
  }
  if (name.length < 1 || name.length > 100) {
    throw new CodeEnvironmentValidationError(
      'Code environment name must contain between 1 and 100 characters',
    );
  }
  if (!isSecureCodeEnvironmentControlURL(baseURL)) {
    throw new CodeEnvironmentValidationError('Code environment control requires secure transport');
  }
  if (workerId != null && !WORKER_ID_PATTERN.test(workerId)) {
    throw new CodeEnvironmentValidationError('Code environment worker id is invalid');
  }
  if (
    input.workerPrincipal != null &&
    !WORKER_PRINCIPAL_ID_PATTERN.test(input.workerPrincipal.id)
  ) {
    throw new CodeEnvironmentValidationError('Code environment worker principal is invalid');
  }
  return { ...input, id, name, baseURL, workerId };
}

function toSummary(
  environment: {
    _id: Types.ObjectId;
    environmentId: string;
    name: string;
    type: 'managed' | 'attached';
  },
  canDelete = false,
): CodeEnvironmentSummary {
  return {
    resourceId: environment._id.toString(),
    id: environment.environmentId,
    name: environment.name,
    type: environment.type,
    canDelete,
  };
}

export function createCodeEnvironmentRegistry(mongoose: typeof import('mongoose')): {
  register: (params: {
    actor: CodeEnvironmentPrincipalContext;
    environment: CodeEnvironmentRegistration;
    maxOwned?: number;
  }) => Promise<CodeEnvironmentSummary>;
  listAccessible: (actor: CodeEnvironmentPrincipalContext) => Promise<CodeEnvironmentSummary[]>;
  listAccessibleConfigurations: (
    actor: CodeEnvironmentPrincipalContext,
  ) => Promise<AccessibleCodeEnvironmentConfiguration[]>;
  remove: (params: {
    actor: CodeEnvironmentPrincipalContext;
    environmentId: string;
    beforeDelete?: (target: CodeEnvironmentLifecycleTarget) => Promise<void>;
  }) => Promise<CodeEnvironmentSummary | null>;
} {
  const methods = createMethods(mongoose);
  const access = new AccessControlService(mongoose);

  async function register({
    actor,
    environment: input,
    maxOwned,
  }: {
    actor: CodeEnvironmentPrincipalContext;
    environment: CodeEnvironmentRegistration;
    maxOwned?: number;
  }): Promise<CodeEnvironmentSummary> {
    const environment = normalizeRegistration(input);
    const createInput = {
      environmentId: environment.id,
      name: environment.name,
      type: environment.type,
      baseURL: environment.baseURL,
      workerId: environment.workerId,
      controlPlaneId: environment.controlPlaneId,
      revocationTokenEnv: environment.revocationTokenEnv,
      workerPrincipal: environment.workerPrincipal,
      createdBy: new Types.ObjectId(actor.userId),
    };
    const created =
      maxOwned == null
        ? await methods.createCodeEnvironment(createInput)
        : await methods.createCodeEnvironmentWithinOwnerLimit(createInput, maxOwned);
    if (created == null) {
      throw new CodeEnvironmentLimitError();
    }
    try {
      const permission = await access.grantPermission({
        principalType: PrincipalType.USER,
        principalId: actor.userId,
        resourceType: ResourceType.CODE_ENVIRONMENT,
        resourceId: created._id,
        accessRoleId: AccessRoleIds.CODE_ENVIRONMENT_OWNER,
        grantedBy: actor.userId,
      });
      if (permission == null) {
        throw new Error('Unable to grant code environment ownership');
      }
      return toSummary(created, true);
    } catch (error) {
      await methods.deleteCodeEnvironmentById(created._id);
      throw error;
    }
  }

  async function findAccessible(actor: CodeEnvironmentPrincipalContext) {
    const principals = await methods.getUserPrincipals(actor);
    const ids = await access.findAccessibleResourcesForPrincipals({
      principalsList: principals,
      resourceType: ResourceType.CODE_ENVIRONMENT,
      requiredPermissions: PermissionBits.VIEW,
    });
    const environments = await methods.findCodeEnvironmentsByIds(ids);
    const userId = actor.userId.toString();
    return environments.filter(
      (environment) =>
        environment.workerPrincipal?.type !== 'user' || environment.workerPrincipal.id === userId,
    );
  }

  async function listAccessible(
    actor: CodeEnvironmentPrincipalContext,
  ): Promise<CodeEnvironmentSummary[]> {
    const environments = await findAccessible(actor);
    const permissions = await access.getResourcePermissionsMap({
      userId: actor.userId,
      role: actor.role ?? '',
      resourceType: ResourceType.CODE_ENVIRONMENT,
      resourceIds: environments.map((environment) => environment._id),
    });
    return environments.map((environment) => {
      const permission = permissions.get(environment._id.toString()) ?? 0;
      return toSummary(environment, (permission & PermissionBits.DELETE) === PermissionBits.DELETE);
    });
  }

  async function listAccessibleConfigurations(
    actor: CodeEnvironmentPrincipalContext,
  ): Promise<AccessibleCodeEnvironmentConfiguration[]> {
    const environments = await findAccessible(actor);
    return environments.map((environment) => ({
      id: environment.environmentId,
      name: environment.name,
      type: environment.type,
      baseURL: environment.baseURL,
      owner: 'principal',
      workerId: environment.workerId,
    }));
  }

  async function remove({
    actor,
    environmentId,
    beforeDelete,
  }: {
    actor: CodeEnvironmentPrincipalContext;
    environmentId: string;
    beforeDelete?: (target: CodeEnvironmentLifecycleTarget) => Promise<void>;
  }): Promise<CodeEnvironmentSummary | null> {
    const environment = await methods.findCodeEnvironmentByEnvironmentId(environmentId);
    if (environment == null) return null;
    if (
      environment.workerPrincipal?.type === 'user' &&
      environment.workerPrincipal.id !== actor.userId.toString()
    ) {
      return null;
    }
    const allowed = await access.checkPermission({
      userId: actor.userId.toString(),
      role: actor.role,
      resourceType: ResourceType.CODE_ENVIRONMENT,
      resourceId: environment._id,
      requiredPermission: PermissionBits.DELETE,
    });
    if (!allowed) return null;
    const Agent = mongoose.models.Agent;
    if (Agent != null && (await Agent.exists({ code_environment_id: environmentId })) != null) {
      throw new CodeEnvironmentInUseError(environmentId);
    }

    await beforeDelete?.({
      ...toSummary(environment),
      baseURL: environment.baseURL,
      workerId: environment.workerId,
      controlPlaneId: environment.controlPlaneId,
      revocationTokenEnv: environment.revocationTokenEnv,
      workerPrincipal: environment.workerPrincipal,
    });
    const deleted = await methods.deleteCodeEnvironmentById(environment._id);
    if (deleted == null) return null;
    try {
      await access.removeAllPermissions({
        resourceType: ResourceType.CODE_ENVIRONMENT,
        resourceId: environment._id,
      });
    } catch (error) {
      logger.warn('[code-environments] environment deleted with orphaned ACL entries', error);
    }
    return toSummary(deleted, true);
  }

  return { register, listAccessible, listAccessibleConfigurations, remove };
}

export class CodeEnvironmentInUseError extends Error {
  constructor(public readonly environmentId: string) {
    super(`Code environment is still referenced by an agent: ${environmentId}`);
    this.name = 'CodeEnvironmentInUseError';
  }
}
