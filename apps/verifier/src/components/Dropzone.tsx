import { Stack, Text } from "@mantine/core";
import { Dropzone as MantineDropzone, type DropzoneProps as MantineDropzoneProps } from "@mantine/dropzone";
import type { ReactNode } from "react";

interface DropzoneProps extends Omit<MantineDropzoneProps, "onDrop" | "children"> {
  onFile: (file: File) => void;
  browseLabel?: string;
  children: ReactNode;
}

export function Dropzone({ onFile, browseLabel = "or choose a file", children, ...rest }: DropzoneProps) {
  return (
    <MantineDropzone onDrop={(files) => files[0] && onFile(files[0])} multiple={false} mt="md" {...rest}>
      <Stack align="center" gap={4} py="lg">
        <Text>{children}</Text>
        <Text size="sm" c="dimmed">
          {browseLabel}
        </Text>
      </Stack>
    </MantineDropzone>
  );
}
