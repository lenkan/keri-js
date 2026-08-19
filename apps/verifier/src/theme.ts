import { Alert, Card, createTheme } from "@mantine/core";

export const theme = createTheme({
  primaryColor: "blue",
  components: {
    CardSection: Card.Section.extend({
      defaultProps: { withBorder: true, inheritPadding: true, py: "md" },
    }),
    Alert: Alert.extend({
      defaultProps: { color: "red", variant: "light", mt: "md" },
    }),
  },
});
