"""Tests for ReconStrategy (pyrit.strategies.recon_strategy)."""

import pytest
from pyrit.strategies.recon_strategy import ReconStrategy, ReconHypothesis, ReconPhase


class TestReconStrategyInitialization:
    """Test ReconStrategy initialization and configuration."""

    def test_strategy_creation(self):
        """Test that ReconStrategy can be instantiated."""
        strategy = ReconStrategy(target_model="test-model")
        assert strategy is not None
        assert hasattr(strategy, "scope")
        assert hasattr(strategy, "hypotheses")
        assert hasattr(strategy, "findings")

    def test_scope_config_exists(self):
        """Test that scope configuration is initialized."""
        strategy = ReconStrategy(target_model="gpt-4")
        assert isinstance(strategy.scope, dict)
        assert "target_model" in strategy.scope
        assert "in_scope_capabilities" in strategy.scope
        assert "safe_harbor_enforced" in strategy.scope

    def test_scope_modification(self):
        """Test that scope can be modified."""
        strategy = ReconStrategy(target_model="claude-3-opus")
        strategy.define_scope(
            in_scope=["text_generation"],
            out_of_scope=["image_generation"],
            safe_harbor=True
        )
        assert "text_generation" in strategy.scope["in_scope_capabilities"]
        assert "image_generation" in strategy.scope["out_of_scope_items"]


class TestPhaseExecution:
    """Test execution of six-phase methodology."""

    def test_phase_1_scope_lock(self):
        """Test Phase 1: Scope Lock."""
        strategy = ReconStrategy(target_model="gpt-4")
        strategy.define_scope(
            in_scope=["reasoning"],
            out_of_scope=["code_execution"],
            safe_harbor=True
        )
        assert strategy.phases[1].completed is True

    def test_phase_2_recon_loading(self):
        """Test Phase 2: Recon data loading."""
        strategy = ReconStrategy(target_model="gpt-4")
        strategy.load_recon_data()
        assert strategy.phases[2].completed is True
        assert len(strategy.model_capabilities) > 0

    def test_phase_3_setup(self):
        """Test Phase 3: Setup and hypothesis configuration."""
        strategy = ReconStrategy(target_model="gpt-4")
        strategy.configure_orchestrator()
        assert strategy.phases[3].completed is True
        assert len(strategy.hypotheses) > 0

    def test_hypothesis_loading(self):
        """Test that hypotheses are loaded with expected structure."""
        strategy = ReconStrategy(target_model="gpt-4")
        strategy.configure_orchestrator()

        for hypothesis in strategy.hypotheses:
            assert isinstance(hypothesis, ReconHypothesis)
            assert hypothesis.name
            assert hypothesis.test_prompts
            assert hypothesis.success_indicators


class TestFindingExport:
    """Test Phase 5-6: Documentation and export."""

    def test_export_empty_findings_json(self):
        """Test JSON export with no findings."""
        strategy = ReconStrategy(target_model="gpt-4")
        json_output = strategy.export_findings(format="json")

        assert isinstance(json_output, str)
        assert "[]" in json_output

    def test_export_empty_findings_markdown(self):
        """Test Markdown export with no findings."""
        strategy = ReconStrategy(target_model="gpt-4")
        md_output = strategy.export_findings(format="markdown")

        assert isinstance(md_output, str)
        assert "# LLM Red-Team Findings" in md_output

    def test_export_with_findings_json(self):
        """Test JSON export with findings."""
        strategy = ReconStrategy(target_model="gpt-4")

        finding = {
            "title": "Test Vulnerability",
            "severity": "high",
            "description": "Test description",
            "affected_capability": "text_generation",
            "reproduction_steps": ["step1"],
            "impact": "Test impact",
            "remediation": "Fix",
        }
        strategy.findings.append(finding)

        json_output = strategy.export_findings(format="json")
        assert "Test Vulnerability" in json_output
        assert "high" in json_output

    def test_export_invalid_format(self):
        """Test that invalid export format raises error."""
        strategy = ReconStrategy(target_model="gpt-4")

        with pytest.raises(ValueError):
            strategy.export_findings(format="invalid_format")


class TestReconHypothesis:
    """Test ReconHypothesis dataclass."""

    def test_hypothesis_creation(self):
        """Test that ReconHypothesis can be created."""
        hyp = ReconHypothesis(
            name="test_hypothesis",
            description="Test description",
            category="test_category",
            test_prompts=["prompt1"],
            success_indicators=["indicator1"],
        )

        assert hyp.name == "test_hypothesis"
        assert hyp.severity_if_confirmed == "medium"

    def test_hypothesis_custom_severity(self):
        """Test ReconHypothesis with custom severity."""
        hyp = ReconHypothesis(
            name="critical_test",
            description="desc",
            category="critical_cat",
            test_prompts=["prompt"],
            success_indicators=["indicator"],
            severity_if_confirmed="critical",
        )

        assert hyp.severity_if_confirmed == "critical"


class TestPhaseStatus:
    """Test phase status tracking."""

    def test_initial_phase_status(self):
        """Test that initial phases are not completed."""
        strategy = ReconStrategy(target_model="gpt-4")
        status = strategy.get_phase_status()

        assert status["Phase 1 (Scope Lock)"] is False
        assert status["Phase 2 (Recon)"] is False

    def test_phase_completion_tracking(self):
        """Test that phases mark completion correctly."""
        strategy = ReconStrategy(target_model="gpt-4")
        strategy.define_scope(in_scope=["text"], out_of_scope=[], safe_harbor=True)
        strategy.load_recon_data()

        status = strategy.get_phase_status()
        assert status["Phase 1 (Scope Lock)"] is True
        assert status["Phase 2 (Recon)"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
