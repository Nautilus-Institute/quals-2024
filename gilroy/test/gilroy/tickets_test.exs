defmodule Gilroy.TicketsTest do
  use Gilroy.DataCase

  alias Gilroy.Tickets

  describe "tickets" do
    alias Gilroy.Tickets.Ticket

    import Gilroy.TicketsFixtures

    @invalid_attrs %{seed: nil, db_size: nil, slug: nil, reset_at: nil, database: nil}

    test "list_tickets/0 returns all tickets" do
      ticket = ticket_fixture()
      assert Tickets.list_tickets() == [ticket]
    end

    test "get_ticket!/1 returns the ticket with given id" do
      ticket = ticket_fixture()
      assert Tickets.get_ticket!(ticket.id) == ticket
    end

    test "create_ticket/1 with valid data creates a ticket" do
      valid_attrs = %{
        seed: 42,
        db_size: 42,
        slug: "some slug",
        reset_at: ~N[2024-01-06 03:15:00],
        database: "some database"
      }

      assert {:ok, %Ticket{} = ticket} = Tickets.create_ticket(valid_attrs)
      assert ticket.seed == 42
      assert ticket.db_size == 42
      assert ticket.slug == "some slug"
      assert ticket.reset_at == ~N[2024-01-06 03:15:00]
      assert ticket.database == "some database"
    end

    test "create_ticket/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = Tickets.create_ticket(@invalid_attrs)
    end

    test "update_ticket/2 with valid data updates the ticket" do
      ticket = ticket_fixture()

      update_attrs = %{
        seed: 43,
        db_size: 43,
        slug: "some updated slug",
        reset_at: ~N[2024-01-07 03:15:00],
        database: "some updated database"
      }

      assert {:ok, %Ticket{} = ticket} = Tickets.update_ticket(ticket, update_attrs)
      assert ticket.seed == 43
      assert ticket.db_size == 43
      assert ticket.slug == "some updated slug"
      assert ticket.reset_at == ~N[2024-01-07 03:15:00]
      assert ticket.database == "some updated database"
    end

    test "update_ticket/2 with invalid data returns error changeset" do
      ticket = ticket_fixture()
      assert {:error, %Ecto.Changeset{}} = Tickets.update_ticket(ticket, @invalid_attrs)
      assert ticket == Tickets.get_ticket!(ticket.id)
    end

    test "delete_ticket/1 deletes the ticket" do
      ticket = ticket_fixture()
      assert {:ok, %Ticket{}} = Tickets.delete_ticket(ticket)
      assert_raise Ecto.NoResultsError, fn -> Tickets.get_ticket!(ticket.id) end
    end

    test "change_ticket/1 returns a ticket changeset" do
      ticket = ticket_fixture()
      assert %Ecto.Changeset{} = Tickets.change_ticket(ticket)
    end
  end
end
