import { ResizerGrip, ResizerTrack } from "./PanelResizer.styled";

function PanelResizer({ onPointerDown, active }) {
  return (
    <ResizerTrack
      active={active ? 1 : 0}
      onPointerDown={onPointerDown}
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize network topology panel"
    >
      <ResizerGrip active={active ? 1 : 0} />
    </ResizerTrack>
  );
}

export default PanelResizer;
