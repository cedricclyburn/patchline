'use strict';

// Static catalog snapshot. In production this would be synced nightly from the ERP.
const PARTS = [
  {
    partNumber: 'AS-1042-TI',
    name: 'Titanium hex bolt, 1/4-28 UNF',
    category: 'fasteners',
    material: 'Ti-6Al-4V',
    spec: 'NAS6604',
    supplier: { code: 'SUP-017', name: 'Cascade Fastener Co.', cage: '1A2B3' },
    unitPriceUsd: 4.85,
    leadTimeDays: 21,
    stock: 12500,
  },
  {
    partNumber: 'AS-2210-AL',
    name: 'Aluminium wing rib bracket',
    category: 'structures',
    material: '7075-T6',
    spec: 'AMS4045',
    supplier: { code: 'SUP-042', name: 'Northline Aerostructures', cage: '4C5D6' },
    unitPriceUsd: 312.0,
    leadTimeDays: 45,
    stock: 80,
  },
  {
    partNumber: 'AS-3307-CF',
    name: 'Carbon fibre fairing panel',
    category: 'structures',
    material: 'CFRP T800',
    spec: 'BMS8-276',
    supplier: { code: 'SUP-042', name: 'Northline Aerostructures', cage: '4C5D6' },
    unitPriceUsd: 1890.5,
    leadTimeDays: 60,
    stock: 6,
  },
  {
    partNumber: 'AS-4120-HY',
    name: 'Hydraulic line fitting, 37 deg flare',
    category: 'hydraulics',
    material: 'CRES 321',
    spec: 'AS4395',
    supplier: { code: 'SUP-108', name: 'Meridian Fluid Systems' },
    unitPriceUsd: 27.4,
    leadTimeDays: 14,
    stock: 2300,
  },
  {
    partNumber: 'AS-5001-EL',
    name: 'Wire harness connector, 55-pin',
    category: 'electrical',
    material: 'Composite shell',
    spec: 'MIL-DTL-38999',
    supplier: { code: 'SUP-233', name: 'Aurora Interconnect', cage: '7E8F9' },
    unitPriceUsd: 146.25,
    leadTimeDays: 30,
    stock: 410,
  },
];

function normalize(partNumber) {
  return String(partNumber || '').trim().toUpperCase();
}

module.exports = { PARTS, normalize };
