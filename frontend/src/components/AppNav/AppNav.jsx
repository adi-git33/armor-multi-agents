import { HeaderContainer, LogoStyle, NavBar, NavChip, NavGlyph, NavLabel } from "./AppNav.styled";
import logo from "../../assets/logo.png";

const TABS = [
  { id: "live", label: "LIVE DASHBOARD" },
  { id: "validation", label: "VALIDATION" },
];

function AppNav({ tab, setTab }) {
  return (
    <HeaderContainer>
      <LogoStyle src={logo} alt="logo" />
      <NavBar>
        {TABS.map((t) => {
          const active = tab === t.id;
          return (
            <NavChip key={t.id} active={active} onClick={() => setTab(t.id)}>
              <NavGlyph active={active} />
              <NavLabel active={active}>{t.label}</NavLabel>
            </NavChip>
          );
        })}
      </NavBar>
    </HeaderContainer>
  );
}

export default AppNav;
