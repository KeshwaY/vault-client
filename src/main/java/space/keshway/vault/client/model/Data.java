package space.keshway.vault.client.model;

import java.util.List;

// TODO: check for nulls and empty
public record Data(DataType type, List<String> values) {}
