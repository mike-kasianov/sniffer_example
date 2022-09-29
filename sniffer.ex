defmodule Sniffer do
  use GenServer

  # https://github.com/torvalds/linux/blob/v5.18/include/linux/socket.h#L195
  @af_packet 17

  # https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/if_ether.h#L131
  @eth_p_all 0x0003

  @socket_recv_buffer_size 1500

  # API

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  # Callbacks

  @impl GenServer
  def init(opts) do
    socket = socket_open!()

    if_name = Keyword.get(opts, :if_name, :all)
    socket_bind!(socket, if_name)

    case Keyword.get(opts, :promiscuous, false) do
      true -> socket_set_promiscuous_mode!(socket, if_name)
      false -> :ok
    end

    socket_recieve(socket)

    {:ok, socket}
  end

  @impl GenServer
  def handle_cast({:socket_data, source, data}, socket) do
    IO.inspect(source, label: "SOURCE")

    IO.puts("-------------------")

    case parse_ethernet_frame(data) do
      {:ok, frame} ->
        IO.inspect(frame, label: "Ethernet frame")
      :error ->
        IO.puts("Unknonw data")
    end

    socket_recieve(socket)

    {:noreply, socket}
  end

  def handle_cast({:socket_error, reason}, socket) do
    IO.inspect(reason, label: "SOCKET ERROR")

    {:noreply, socket}
  end

  @impl GenServer
  def handle_info({:"$socket", socket, :select, _select_handle}, socket) do
    socket_recieve(socket)

    {:noreply, socket}
  end

  # Internal

  def socket_open!() do
    # The protocol @eth_p_all must be provided in network byte order (big endian).
    # See https://man7.org/linux/man-pages/man7/packet.7.html for details
    <<eth_p_all_host::big-unsigned-integer-size(16)>> = <<@eth_p_all::native-unsigned-integer-size(16)>>

    {:ok, socket} = :socket.open(@af_packet, :raw, eth_p_all_host)
    socket
  end

  defp socket_bind!(_socket, :all), do: :ok

  defp socket_bind!(socket, if_name) do
    {:ok, if_index} = :binary.bin_to_list(if_name) |> :net.if_name2index()

    # Put real values only for sll_protocol and sll_ifindex.
    sll_protocol = @eth_p_all
    sll_ifindex = if_index
    sll_hatype = 0
    sll_pkttype = 0
    sll_halen = 0
    sll_addr = <<0::native-unsigned-size(8)-unit(8)>>

    # The sockaddr_ll structure is described here https://man7.org/linux/man-pages/man7/packet.7.html
    addr = <<
      sll_protocol::big-unsigned-size(16),
      sll_ifindex::native-unsigned-size(32),
      sll_hatype::native-unsigned-size(16),
      sll_pkttype::native-unsigned-size(8),
      sll_halen::native-unsigned-size(8),
      sll_addr::binary
    >>

    sockaddr = %{
      family: @af_packet,
      addr: addr
    }

    :ok = :socket.bind(socket, sockaddr)
  end

  defp socket_set_promiscuous_mode!(socket, if_name) do
    if_name = :binary.bin_to_list(if_name)

    :ok = :socket.ioctl(socket, :sifflags, if_name, %{promisc: true})
  end

  defp socket_recieve(socket) do
    case :socket.recvfrom(socket, @socket_recv_buffer_size, :nowait) do
      {:ok, {source, data}} ->
        GenServer.cast(self(), {:socket_data, source, data})

      {:select, _select_info} ->
        :ok

      {:error, reason} ->
        GenServer.cast(self(), {:socket_error, reason})
    end
  end

  # See https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/if_ether.h#L171 for the sturcture description
  defp parse_ethernet_frame(<<
    destination_mac::binary-size(6),
    source_mac::binary-size(6),
    protocol::big-unsigned-integer-size(16),
    rest::binary
  >>) do
    frame = %{
      destination_mac: humanize_mac(destination_mac),
      source_mac: humanize_mac(source_mac),
      protocol: humanize_protocol(protocol),
      payload: rest
    }

    {:ok, frame}
  end

  defp parse_ethernet_frame(_) do
    :error
  end

  defp humanize_mac(data) do
    data
    |> :binary.bin_to_list()
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.join(":")
  end

  # See the list of available protocols here https://github.com/torvalds/linux/blob/v5.18/include/uapi/linux/if_ether.h#L52
  def humanize_protocol(0x0800), do: "IP v4"
  def humanize_protocol(protocol), do: "Unknown (#{Integer.to_string(protocol, 16)})"
end
