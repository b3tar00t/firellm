from firellm.rag_simulator import RAGSimulator


def main() -> None:
    simulator = RAGSimulator.from_sample()
    query = "What is the secret code?"
    result = simulator.simulate(query)
    print("Query:", query)
    print("---")
    print(result.details)
    print("---")
    print("Metadata:", result.metadata)


if __name__ == "__main__":
    main()
