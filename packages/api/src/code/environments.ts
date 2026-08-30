import { Types } from 'mongoose';
import { createMethods } from '@librechat/data-schemas';
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
};

export type CodeEnvironmentRegistration = {
  id: string;
  name: string;
  type: 'managed' | 'attached';
  baseURL: string;
  workerId?: string;
  controlPlaneId?: string;
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

function toSummary(environment: {
  _id: Types.ObjectId;
  environmentId: string;
  name: string;
  type: 'managed' | 'attached';
}): CodeEnvironmentSummary {
  return {
    resourceId: environment._id.toString(),
    id: environment.environmentId,
    name: environment.name,
    type: environment.type,
  };
}

export function createCodeEnvironmentRegistry(mongoose: typeof import('mongoose')): {
  register: (params: {
    actor: CodeEnvironmentPrincipalContext;
    environment: CodeEnvironmentRegistration;
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
  }: {
    actor: CodeEnvironmentPrincipalContext;
    environment: CodeEnvironmentRegistration;
  }): Promise<CodeEnvironmentSummary> {
    const environment = normalizeRegistration(input);
    const created = await methods.createCodeEnvironment({
      environmentId: environment.id,
      name: environment.name,
      type: environment.type,
      baseURL: environment.baseURL,
      workerId: environment.workerId,
      controlPlaneId: environment.controlPlaneId,
      workerPrincipal: environment.workerPrincipal,
      createdBy: new Types.ObjectId(actor.userId),
    });
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
      return toSummary(created);
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
    return environments.map(toSummary);
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
    const allowed = await access.checkPermission({
      userId: actor.userId.toString(),
      role: actor.role,
      resourceType: ResourceType.CODE_ENVIRONMENT,
      resourceId: environment._id,
      requiredPermission: PermissionBits.DELETE,
    });
    if (!allowed) return null;

    await beforeDelete?.({
      ...toSummary(environment),
      baseURL: environment.baseURL,
      workerId: environment.workerId,
      controlPlaneId: environment.controlPlaneId,
      workerPrincipal: environment.workerPrincipal,
    });
    const deleted = await methods.deleteCodeEnvironmentById(environment._id);
    if (deleted == null) return null;
    await access.removeAllPermissions({
      resourceType: ResourceType.CODE_ENVIRONMENT,
      resourceId: environment._id,
    });
    return toSummary(deleted);
  }

  return { register, listAccessible, listAccessibleConfigurations, remove };
}
