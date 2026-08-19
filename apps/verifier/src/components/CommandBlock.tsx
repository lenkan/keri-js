import { Box, Button, CopyButton, Group } from "@mantine/core";

export function CommandBlock({ children }: { children: string }) {
  return (
    <Group
      wrap="nowrap"
      align="flex-start"
      gap="xs"
      p="xs"
      bg="gray.0"
      style={{ borderRadius: "var(--mantine-radius-sm)" }}
    >
      <Box
        component="pre"
        m={0}
        fz="xs"
        ff="monospace"
        // minWidth:0 lets this shrink below its content width so long lines scroll
        // here instead of pushing the copy button out of the row.
        style={{ flex: 1, minWidth: 0, overflowX: "auto" }}
      >
        {children}
      </Box>
      <CopyButton value={children} timeout={1500}>
        {({ copied, copy }) => (
          <Button type="button" variant="subtle" size="compact-xs" onClick={copy}>
            {copied ? "Copied" : "Copy"}
          </Button>
        )}
      </CopyButton>
    </Group>
  );
}
