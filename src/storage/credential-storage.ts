import type { CredentialBody, IssueEvent, Message, RegistryInceptEventBody, RevokeEvent } from "#keri/core";

export interface CredentialStorage {
  getCredentialEvents(id: string): Generator<Message<IssueEvent | RevokeEvent>>;
  getRegistry(id: string): Message<RegistryInceptEventBody> | null;
  getRegistriesByOwner(owner: string): Generator<Message<RegistryInceptEventBody>>;
  getCredential(id: string): CredentialBody | null;
  getCredentialsByRegistry(registryId: string): CredentialBody[];
}
