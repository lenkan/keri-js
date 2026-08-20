import type { CredentialBody, IssueEventBody, Message, RegistryInceptEventBody, RevokeEventBody } from "keri";

export interface CredentialStorage {
  getCredentialEvents(id: string): Generator<Message<IssueEventBody | RevokeEventBody>>;
  getRegistry(id: string): Message<RegistryInceptEventBody> | null;
  getRegistriesByOwner(owner: string): Generator<Message<RegistryInceptEventBody>>;
  getCredential(id: string): CredentialBody | null;
  getCredentialsByRegistry(registryId: string): CredentialBody[];
}
