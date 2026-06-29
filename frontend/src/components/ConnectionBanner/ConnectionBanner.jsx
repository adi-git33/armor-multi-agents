import { Snackbar } from "@mui/material";
import { ConnectionAlert } from "./ConnectionBanner.styled";

function ConnectionBanner({ connected }) {
  return (
    <Snackbar open={!connected} anchorOrigin={{ vertical: "bottom", horizontal: "center" }}>
      <ConnectionAlert severity="warning">
        Connecting to server...
      </ConnectionAlert>
    </Snackbar>
  );
}

export default ConnectionBanner;
