package space.keshway.vault.client.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record Data(@NotNull DataType type, @NotEmpty List<String> values) {}
