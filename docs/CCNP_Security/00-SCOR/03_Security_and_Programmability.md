## 03 Software-Defined Networking Security and Network Programmability

### Introduction to Software-Defined Networking
- The next generation of hardware and software components in enterprise networks must support both the rapid introduction and the rapid evolution of new technologies and solutions. Network infrastructure solutions must keep pace with the business environment and support modern capabilities that help drive simplification within the network.

- These elements have fueled the creation of `software-defined networking (SDN)`. SDN was originally created to decouple control from the forwarding functions in networking equipment. This is done to use software to centrally manage and “program” the hardware and virtual networking appliances to perform forwarding.

#### Traditional Networking Planes
- In traditional networking, there are three different “planes” or elements that allow network devices to operate: the `management`, `control`, and `data planes`. 
  - *`Management Plane`* 
    - Configuration and monitoring 
    - Typically done via the traditional CLI or GUI
    - Each vendor has its proprietary way to configure its
  - *`Control Plane`*
    - Layer 2 protocols and control
    - Layer 3 protocols (e.g., OSPF, RIP, BGP, etc.)
  - *`Data Plane`* 
    - Institutes how data is forwarded inside the hardware from interface to interface

- The control plane has always been separated from the data plane. There was no central brain (or controller) that controlled the configuration and forwarding. The `Routers`, `switches`, and `firewalls` were managed by the `command-line interface (CLI)`, `graphical user interfaces (GUIs)`, and `custom Tcl scripts`. For instance, the firewalls were managed by the `Adaptive Security Device Manager (ASDM)`, while the routers were managed by the `CLI`. Each device has its `own brain` and does not really exchange any intelligent information with the rest of the devices.

- *`So What’s Different with SDN?`* - SDN introduced the notion of a `centralized controller`. The `SDN` controller has a global view of the network, and it uses a common management protocol to configure the network infrastructure devices. The `SDN controller` can also calculate `reachability` information from many systems in the network and pushes a set of flows inside the switches. The flows are used by the `hardware` to do the `forwarding`. Here you can see a clear transition from a distributed `semi-intelligent brain` approach to a `central and intelligent brain` approach.

- *`TIP:-`* Example of an open source implementation of SDN controllers is the `Open vSwitch (OVS)` project using the `OVS Database (OVSDB)` management protocol and the `OpenFlow` protocol. Another example is the `Cisco Application Policy Infrastructure Controller (Cisco APIC)`. "Cisco APIC" is the main architectural component and the brain of the `Cisco Application Centric Infrastructure (ACI)` solution. 

- SDN changed a few things in the `management`, `control`, and `data planes`. However, the big change was in the `control` and `data planes` in software-based `switches` and `routers` (including `virtual switches` inside of `hypervisors`). For instance, the `Open vSwitch` project started some of these changes across the industry.

- SDN provides numerous benefits in the area of `management plane`. These benefits are in both `physical switches` and `virtual switches`. SDN is now widely adopted in data centers. A great example of this is `Cisco ACI`.

#### Cisco ACI Solution
- Cisco ACI provides the ability to automate setting networking policies and configurations in a very flexible and scalable way. The Cisco ACI scenario shown in Figure 3-3 uses a leaf-and-spine topology.

- The leaf switches have ports connected to traditional Ethernet devices (for example, servers, firewalls, routers, and so on). Leaf switches are typically deployed at the edge of the fabric. These leaf switches provide the Virtual Extensible LAN (VXLAN) tunnel endpoint (VTEP) function. VXLAN is a network virtualization technology that leverages an encapsulation technique (similar to VLANs) to encapsulate Layer 2 Ethernet frames within UDP packets (over UDP port 4789, by default).

- NOTE The section “VXLAN and Network Overlays,” later in the chapter, will discuss VXLAN and overlays in more detail.

- In Cisco ACI, the IP address that represents the leaf VTEP is called the physical tunnel endpoint (PTEP). The leaf switches are responsible for routing or bridging tenant packets and for applying network policies.


