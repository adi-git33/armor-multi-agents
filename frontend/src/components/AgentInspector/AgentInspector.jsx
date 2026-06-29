import {
  Drawer,
  Stack,
} from "@mui/material";
import { stateColor } from "../../dashboard/utils";
import {
  AgentSubtitle,
  AgentTitle,
  BeliefItem,
  BeliefKey,
  BeliefsList,
  BeliefRow,
  BeliefValue,
  BudgetLabel,
  BudgetMetaRow,
  BudgetProgress,
  BudgetValue,
  CloseButton,
  CloseGlyph,
  Content,
  DrawerContent,
  GoalText,
  GoalsList,
  Header,
  IntentionCard,
  IntentionRow,
  PlanText,
  SectionTitle,
  StateText,
  StatusDot,
  TaskText,
} from "./AgentInspector.styled";

function AgentInspector({ agent, onClose }) {
  if (!agent) return null;
  const sc = stateColor(agent.state);
  const pct = Math.max(5, Math.min(100, ((agent.budget - 20) / agent.budget) * 100));

  return (
    <Drawer anchor="right" open={Boolean(agent)} onClose={onClose}>
      <DrawerContent>
        <Header>
          <Stack direction="row" spacing={1.25} alignItems="center">
            <StatusDot dotcolor={sc} />
            <div>
              <AgentTitle>{agent.code}</AgentTitle>
              <AgentSubtitle>{agent.typeName} · {agent.seg}</AgentSubtitle>
            </div>
          </Stack>
          <CloseButton onClick={onClose} size="small">
            <CloseGlyph>x</CloseGlyph>
          </CloseButton>
        </Header>

        <Content>
          <div>
            <SectionTitle>CURRENT INTENTION</SectionTitle>
            <IntentionCard>
              <IntentionRow>
                <PlanText>{agent.plan}</PlanText>
                <StateText statecolor={sc}>{agent.state.toUpperCase()}</StateText>
              </IntentionRow>
              <TaskText>{agent.task}</TaskText>
              <BudgetMetaRow>
                <BudgetLabel>DEADLINE BUDGET</BudgetLabel>
                <BudgetValue>{agent.budget} ms</BudgetValue>
              </BudgetMetaRow>
              <BudgetProgress variant="determinate" value={pct} barcolor={sc} />
            </IntentionCard>
          </div>

          <div>
            <SectionTitle>WHAT IT KNOWS</SectionTitle>
            <BeliefsList>
              {(agent.beliefs || []).map((b, i) => (
                <BeliefItem key={`${b.k}-${i}`} showborder={i > 0 ? 1 : 0}>
                  <BeliefRow>
                    <BeliefKey>{b.k}</BeliefKey>
                    <BeliefValue valuecolor={b.vColor}>{b.v}</BeliefValue>
                  </BeliefRow>
                </BeliefItem>
              ))}
            </BeliefsList>
          </div>

          <div>
            <SectionTitle>GOALS</SectionTitle>
            <GoalsList>
              {(agent.desires || []).map((d, i) => (
                <GoalText key={`${d}-${i}`}>
                  {"› "}
                  {d}
                </GoalText>
              ))}
            </GoalsList>
          </div>
        </Content>
      </DrawerContent>
    </Drawer>
  );
}

export default AgentInspector;
