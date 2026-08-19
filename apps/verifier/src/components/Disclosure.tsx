import { Accordion } from "@mantine/core";
import type { ReactNode } from "react";

export function Disclosure({ summary, children }: { summary: ReactNode; children: ReactNode }) {
  return (
    <Accordion variant="separated" mt="md">
      <Accordion.Item value="disclosure">
        <Accordion.Control>{summary}</Accordion.Control>
        <Accordion.Panel>{children}</Accordion.Panel>
      </Accordion.Item>
    </Accordion>
  );
}
